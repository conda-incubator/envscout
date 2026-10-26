package evidence

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"

	stereofile "github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/python"
	"github.com/anchore/syft/syft/source"
	"github.com/bmatcuk/doublestar/v4"
	gorattler "github.com/conda-incubator/go-rattler"
)

const (
	hostPathLimit     = 500000
	hostEntryLimit    = 10000
	hostMetadataLimit = 1 << 20
)

var hostPythonVersionDirectory = regexp.MustCompile(`^python[0-9]+\.[0-9]+t?$`)

func hostIssue(target *Target, capability, path, message string) {
	target.Coverage[capability] = Partial
	if len(target.Issues) < hostEntryLimit {
		target.Issues = append(target.Issues, Issue{Capability: capability, Path: path, Message: message})
	}
}

func collectHostFacts(ctx context.Context, target *Target, req Request, caches map[string]Target) error {
	if Requested(req, "python-distributions") {
		collectHostPython(ctx, target)
	}
	if Requested(req, "host-cache") && ctx.Err() == nil {
		collectHostCache(ctx, target, caches)
	}
	if Requested(req, "installed-lock") && ctx.Err() == nil {
		collectHostPixi(ctx, target, req)
	}
	if err := ctx.Err(); err != nil {
		for capability, state := range target.Coverage {
			if state != NotCollected {
				target.Coverage[capability] = Partial
			}
		}
		return err
	}
	return nil
}

// Reads are root-confined, reject every symlink component, and recheck file type.
func hostLstat(root *os.Root, name string) (fs.FileInfo, error) {
	name = filepath.Clean(name)
	if !filepath.IsLocal(name) {
		return nil, fmt.Errorf("evidence path is outside its root")
	}
	parts := strings.Split(name, string(filepath.Separator))
	for i := range parts {
		info, err := root.Lstat(filepath.Join(parts[:i+1]...))
		if err != nil {
			return nil, err
		}
		if info.Mode()&fs.ModeSymlink != 0 {
			return nil, fmt.Errorf("linked evidence is not followed")
		}
		if i == len(parts)-1 {
			return info, nil
		}
	}
	return nil, fmt.Errorf("empty evidence path")
}

func readHostMetadata(ctx context.Context, root *os.Root, name string, limit int64) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	info, err := hostLstat(root, name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > limit {
		return nil, fmt.Errorf("evidence is not a bounded regular file")
	}
	f, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	opened, err := f.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return nil, fmt.Errorf("evidence changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(evidenceContextReader{ctx, f}, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("evidence exceeds %d bytes", limit)
	}
	return data, ctx.Err()
}

// This resolver is an immutable bounded index, not a full ecosystem Syft source.
// Only the installed-Python cataloger is invoked; supporting files remain confined.
type hostFileResolver struct {
	ctx       context.Context
	root      *os.Root
	base      string
	files     map[string]fs.FileInfo
	paths     []string
	mu        sync.Mutex
	readBytes int64
	readLimit int64
	issue     error
}

func (r *hostFileResolver) local(path string) (string, bool) {
	if filepath.IsAbs(path) {
		var err error
		path, err = filepath.Rel(r.base, path)
		if err != nil {
			return "", false
		}
	}
	path = filepath.Clean(filepath.FromSlash(path))
	return path, filepath.IsLocal(path)
}

func (r *hostFileResolver) HasPath(path string) bool {
	name, ok := r.local(path)
	return ok && r.files[name] != nil
}

func (r *hostFileResolver) FilesByPath(paths ...string) ([]file.Location, error) {
	var found []file.Location
	for _, path := range paths {
		if name, ok := r.local(path); ok && r.files[name] != nil && r.files[name].Mode().IsRegular() {
			found = append(found, file.NewLocation(filepath.Join(r.base, name)))
		}
	}
	return found, r.ctx.Err()
}

func (r *hostFileResolver) FilesByGlob(patterns ...string) ([]file.Location, error) {
	var found []file.Location
	for _, name := range r.paths {
		if r.ctx.Err() != nil {
			break
		}
		if !r.files[name].Mode().IsRegular() {
			continue
		}
		for _, pattern := range patterns {
			matched, err := doublestar.Match(pattern, filepath.ToSlash(filepath.Join(r.base, name)))
			if err != nil {
				r.issue = errors.Join(r.issue, err)
				return found, err
			}
			if matched {
				if len(found) >= hostEntryLimit {
					err := fmt.Errorf("host metadata entry limit exceeded (%d)", hostEntryLimit)
					r.issue = errors.Join(r.issue, err)
					return found, err
				}
				found = append(found, file.NewLocation(filepath.Join(r.base, name)))
				break
			}
		}
	}
	return found, r.ctx.Err()
}

func (*hostFileResolver) FilesByMIMEType(...string) ([]file.Location, error) { return nil, nil }

func (r *hostFileResolver) RelativeFileByPath(_ file.Location, path string) *file.Location {
	found, _ := r.FilesByPath(path)
	if len(found) == 0 {
		return nil
	}
	return &found[0]
}

func (r *hostFileResolver) AllLocations(ctx context.Context) <-chan file.Location {
	out := make(chan file.Location)
	go func() {
		defer close(out)
		for _, name := range r.paths {
			select {
			case out <- file.NewLocation(filepath.Join(r.base, name)):
			case <-ctx.Done():
				return
			}
		}
	}()
	return out
}

func (r *hostFileResolver) FileMetadataByLocation(location file.Location) (file.Metadata, error) {
	name, ok := r.local(location.RealPath)
	if !ok || r.files[name] == nil {
		return file.Metadata{}, fs.ErrNotExist
	}
	info := r.files[name]
	return file.Metadata{FileInfo: info, Path: location.RealPath, Type: stereofile.TypeFromMode(info.Mode())}, nil
}

func (r *hostFileResolver) FileContentsByLocation(location file.Location) (io.ReadCloser, error) {
	name, ok := r.local(location.RealPath)
	if !ok || r.files[name] == nil {
		return nil, fs.ErrNotExist
	}
	info := r.files[name]
	r.mu.Lock()
	defer r.mu.Unlock()
	limit := r.readLimit
	if limit == 0 {
		limit = hostMetadataLimit
	}
	if !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > limit || r.readBytes+info.Size() > 256<<20 {
		return nil, fmt.Errorf("host metadata read limit exceeded")
	}
	r.readBytes += info.Size()
	data, err := readHostMetadata(r.ctx, r.root, name, limit)
	return io.NopCloser(bytes.NewReader(data)), err
}

func collectHostPython(ctx context.Context, target *Target) {
	prefix := target.Prefixes[0]
	root, err := os.OpenRoot(prefix.Path)
	if err != nil {
		hostIssue(target, "python-distributions", prefix.Path, "Python filesystem unavailable")
		return
	}
	defer func() { _ = root.Close() }()
	r := &hostFileResolver{ctx: ctx, root: root, base: prefix.Path, files: map[string]fs.FileInfo{}}
	var installations []string
	for _, parent := range []string{"lib", "lib64"} {
		info, err := hostLstat(root, parent)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil || !info.IsDir() {
			hostIssue(target, "python-distributions", filepath.Join(prefix.Path, parent), "Python installation directory is unavailable or linked")
			continue
		}
		dir, err := root.Open(parent)
		if err != nil {
			hostIssue(target, "python-distributions", filepath.Join(prefix.Path, parent), "Python installation directory could not be enumerated")
			continue
		}
		entries, readErr := dir.ReadDir(hostEntryLimit + 1)
		_ = dir.Close()
		if readErr != nil && !errors.Is(readErr, io.EOF) || len(entries) > hostEntryLimit {
			hostIssue(target, "python-distributions", filepath.Join(prefix.Path, parent), "Python installation directory entry limit or enumeration failure")
		}
		if len(entries) > hostEntryLimit {
			entries = entries[:hostEntryLimit]
		}
		for _, entry := range entries {
			if hostPythonVersionDirectory.MatchString(entry.Name()) {
				installations = append(installations, filepath.Join(parent, entry.Name(), "site-packages"))
			}
		}
	}
	installations = append(installations, filepath.Join("Lib", "site-packages"))
	sort.Strings(installations)
	visited := 0
	for _, installation := range installations {
		if _, err := hostLstat(root, installation); os.IsNotExist(err) {
			continue
		}
		if err := indexHostPython(ctx, root, installation, r, target, &visited); err != nil {
			hostIssue(target, "python-distributions", filepath.Join(prefix.Path, installation), err.Error())
		}
		if ctx.Err() != nil || visited > hostPathLimit {
			break
		}
	}
	sort.Strings(r.paths)
	packages, _, err := python.NewInstalledPackageCataloger().Catalog(ctx, r)
	if err != nil || r.issue != nil {
		hostIssue(target, "python-distributions", prefix.Path, "installed Python metadata catalog is incomplete")
	}
	owners := map[string]string{}
	ambiguous := map[string]bool{}
	observed := map[string]bool{}
	for _, located := range prefix.Records {
		if !located.OwnershipKnown {
			hostIssue(target, "python-distributions", located.Path, "conda file ownership metadata is unavailable")
		}
		addOwner := func(path string) {
			local, ok := r.local(path)
			if !ok || r.files[local] == nil {
				return
			}
			if owner := owners[local]; owner != "" && owner != located.Record.Name {
				ambiguous[local] = true
			}
			owners[local] = located.Record.Name
		}
		for _, path := range located.Record.Files {
			addOwner(path)
		}
		for _, path := range located.Record.PathsData.Paths {
			addOwner(path.RelativePath)
		}
	}
	for _, p := range packages {
		if p.Type != pkg.PythonPkg || p.Name == "" || p.Version == "" {
			hostIssue(target, "python-distributions", prefix.Path, "installed Python distribution identity is incomplete")
			continue
		}
		for _, location := range p.Locations.ToSlice() {
			if location.Annotations[pkg.EvidenceAnnotationKey] != pkg.PrimaryEvidenceAnnotation {
				continue
			}
			local, ok := r.local(location.RealPath)
			if !ok {
				continue
			}
			observed[local] = true
			owner := owners[local]
			if ambiguous[local] {
				owner = ""
				hostIssue(target, "python-distributions", location.RealPath, "distribution metadata has multiple conda owners")
			}
			target.Python = append(target.Python, PythonDistribution{Name: p.Name, Version: p.Version, Path: location.RealPath, OwnedBy: owner})
		}
	}
	for _, name := range r.paths {
		lower := strings.ToLower(filepath.ToSlash(name))
		primary := (strings.HasSuffix(lower, ".dist-info/metadata") || strings.HasSuffix(lower, ".egg-info/pkg-info") || (strings.HasSuffix(lower, ".egg-info") && r.files[name].Mode().IsRegular()))
		if primary && !observed[name] && !strings.HasPrefix(filepath.Base(name), "Python-") {
			hostIssue(target, "python-distributions", filepath.Join(prefix.Path, name), "Python distribution metadata did not produce an installed identity")
		}
	}
	sort.Slice(target.Python, func(i, j int) bool { return target.Python[i].Path < target.Python[j].Path })
}

func collectHostCache(ctx context.Context, target *Target, caches map[string]Target) {
	roots := map[string]bool{}
	for _, located := range target.Prefixes[0].Records {
		record := located.Record
		paths := []string{record.ExtractedPackageDir, record.PackageTarballFullPath}
		if record.Link != nil {
			paths = append(paths, record.Link.Source)
		}
		for _, path := range paths {
			if path == "" {
				continue
			}
			if !filepath.IsAbs(path) || strings.ContainsRune(path, 0) || filepath.Dir(filepath.Clean(path)) == string(filepath.Separator) {
				hostIssue(target, "host-cache", located.Path, "record cache path is not a safe absolute location")
				continue
			}
			roots[filepath.Dir(filepath.Clean(path))] = true
		}
	}
	if target.Prefixes[0].RecordCoverage != Complete {
		hostIssue(target, "host-cache", target.Input, "record-referenced cache roots are incomplete")
	}
	var ordered []string
	for path := range roots {
		ordered = append(ordered, path)
	}
	sort.Strings(ordered)
	visited := 0
	seenRoots := map[string]bool{}
	for _, path := range ordered {
		if ctx.Err() != nil {
			break
		}
		info, err := os.Lstat(path)
		if os.IsNotExist(err) {
			continue // recorded build-host paths need not still exist
		}
		if err != nil || !info.IsDir() {
			hostIssue(target, "host-cache", path, "cache root is inaccessible or linked")
			continue
		}
		resolved, err := filepath.EvalSymlinks(path)
		if err != nil {
			hostIssue(target, "host-cache", path, "cache root could not be resolved")
			continue
		}
		if seenRoots[resolved] {
			continue
		}
		seenRoots[resolved] = true
		if facts, found := caches[resolved]; found {
			applyHostCache(target, facts)
			continue
		}
		facts := Target{Coverage: map[string]string{"host-cache": Complete}}
		scanHostCache(ctx, &facts, path, &visited)
		caches[resolved] = facts
		applyHostCache(target, facts)
		if visited > hostPathLimit || len(target.Archives)+len(target.Extracted) >= hostEntryLimit {
			break
		}
	}
	// These are logical byte observations. No deletion or disk savings are inferred.
	sort.Slice(target.Archives, func(i, j int) bool { return target.Archives[i].Path < target.Archives[j].Path })
	sort.Slice(target.Extracted, func(i, j int) bool { return target.Extracted[i].Path < target.Extracted[j].Path })
}

func applyHostCache(target *Target, facts Target) {
	for _, artifacts := range []struct {
		dst *[]Artifact
		src []Artifact
	}{{&target.Archives, facts.Archives}, {&target.Extracted, facts.Extracted}} {
		available := max(0, hostEntryLimit-len(target.Archives)-len(target.Extracted))
		if available < len(artifacts.src) {
			hostIssue(target, "host-cache", target.Input, "cache artifact limit exceeded across roots")
		}
		*artifacts.dst = append(*artifacts.dst, artifacts.src[:min(available, len(artifacts.src))]...)
	}
	target.Issues = append(target.Issues, facts.Issues...)
	if facts.Coverage["host-cache"] != Complete {
		target.Coverage["host-cache"] = Partial
	}
}

func scanHostCache(ctx context.Context, target *Target, path string, visited *int) {
	root, err := os.OpenRoot(path)
	if err != nil {
		hostIssue(target, "host-cache", path, "cache root is not a readable directory")
		return
	}
	entries, err := root.Open(".")
	if err != nil {
		_ = root.Close()
		hostIssue(target, "host-cache", path, "cache directory could not be enumerated")
		return
	}
	children, readErr := entries.ReadDir(hostEntryLimit + 1)
	_ = entries.Close()
	if readErr != nil || len(children) > hostEntryLimit {
		hostIssue(target, "host-cache", path, "cache directory entry limit or enumeration failure")
	}
	if len(children) > hostEntryLimit {
		children = children[:hostEntryLimit]
	}
	sort.Slice(children, func(i, j int) bool { return children[i].Name() < children[j].Name() })
	for _, child := range children {
		if ctx.Err() != nil {
			break
		}
		name := child.Name()
		*visited++
		if *visited > hostPathLimit || len(target.Archives)+len(target.Extracted) >= hostEntryLimit {
			hostIssue(target, "host-cache", path, "cache traversal or artifact entry limit exceeded")
			break
		}
		if child.Type()&fs.ModeSymlink != 0 {
			hostIssue(target, "host-cache", filepath.Join(path, name), "linked cache entry is not followed")
			continue
		}
		if !child.IsDir() {
			if _, err := gorattler.ParseArchiveFilename(name); err != nil {
				continue
			}
			info, err := child.Info()
			if err != nil || !info.Mode().IsRegular() || info.Size() < 0 {
				hostIssue(target, "host-cache", filepath.Join(path, name), "archive is not a readable regular file")
				continue
			}
			target.Archives = append(target.Archives, Artifact{Path: filepath.Join(path, name), Kind: "archive", Bytes: info.Size()})
			continue
		}
		marker := filepath.Join(name, "info/index.json")
		data, err := readHostMetadata(ctx, root, marker, hostMetadataLimit)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			hostIssue(target, "host-cache", filepath.Join(path, marker), "cache marker is not bounded regular metadata")
			continue
		}
		if _, err := gorattler.ParseIndexJSON(data); err != nil {
			hostIssue(target, "host-cache", filepath.Join(path, marker), "cache marker is not valid conda index metadata")
			continue
		}
		// Presence needs only a canonical marker. A recursive payload census is
		// disproportionate for lint; Bytes remains unset rather than guessed.
		target.Extracted = append(target.Extracted, Artifact{Path: filepath.Join(path, name), Kind: "extracted"})
	}
	_ = root.Close()
}

type hostRecordSource struct{ resolver *hostFileResolver }

func (s hostRecordSource) ID() artifact.ID                                  { return artifact.ID(FileID(s.resolver.base)) }
func (s hostRecordSource) FileResolver(source.Scope) (file.Resolver, error) { return s.resolver, nil }
func (s hostRecordSource) Describe() source.Description {
	return source.Description{ID: string(s.ID()), Name: s.resolver.base}
}
func (hostRecordSource) Close() error { return nil }

var _ file.Resolver = (*hostFileResolver)(nil)
