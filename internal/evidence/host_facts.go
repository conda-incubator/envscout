package evidence

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/python"
	gorattler "github.com/conda-incubator/go-rattler"
)

const (
	hostPathLimit     = 500000
	hostEntryLimit    = 10000
	hostMetadataLimit = 1 << 20
)

var hostPythonVersionDirectory = regexp.MustCompile(`^python[0-9]+\.[0-9]+t?$`)

func hostIssue(target *Target, capability, path, message string, causes ...error) {
	target.Coverage[capability] = Partial
	if len(target.Issues) < hostEntryLimit {
		issue := Issue{Capability: capability, Path: path, Message: message}
		for _, err := range causes {
			issue.AccessDenied = issue.AccessDenied || errors.Is(err, fs.ErrPermission)
		}
		target.Issues = append(target.Issues, issue)
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

func collectHostPython(ctx context.Context, target *Target) {
	prefix := target.Prefixes[0]
	root, err := os.OpenRoot(prefix.Path)
	if err != nil {
		hostIssue(target, "python-distributions", prefix.Path, "Python filesystem unavailable", err)
		return
	}
	defer func() { _ = root.Close() }()
	r := &hostFileResolver{ctx: ctx, root: root, base: prefix.Path, files: map[string]fs.FileInfo{}}
	var installations []string
	for _, parent := range []string{"lib", "lib64"} {
		// Linux venvs commonly alias lib64 to lib; it adds no installation root.
		if parent == "lib64" && target.IsVirtualenv() {
			alias, err := root.Readlink(parent)
			if err == nil && alias == "lib" {
				if info, err := hostLstat(root, "lib"); err == nil && info.IsDir() {
					continue
				}
			}
		}
		info, err := hostLstat(root, parent)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil || !info.IsDir() {
			hostIssue(target, "python-distributions", filepath.Join(prefix.Path, parent), "Python installation directory is unavailable or linked", err)
			continue
		}
		dir, err := root.Open(parent)
		if err != nil {
			hostIssue(target, "python-distributions", filepath.Join(prefix.Path, parent), "Python installation directory could not be enumerated", err)
			continue
		}
		entries, readErr := dir.ReadDir(hostEntryLimit + 1)
		_ = dir.Close()
		if readErr != nil && !errors.Is(readErr, io.EOF) || len(entries) > hostEntryLimit {
			hostIssue(target, "python-distributions", filepath.Join(prefix.Path, parent), "Python installation directory entry limit or enumeration failure", readErr)
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
			hostIssue(target, "python-distributions", filepath.Join(prefix.Path, installation), err.Error(), err)
		}
		if ctx.Err() != nil || visited > hostPathLimit {
			break
		}
	}
	sort.Strings(r.paths)
	packages, _, err := python.NewInstalledPackageCataloger().Catalog(ctx, r)
	if err != nil || r.issue != nil {
		hostIssue(target, "python-distributions", prefix.Path, "installed Python metadata catalog is incomplete", err, r.issue)
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
			hostIssue(target, "host-cache", path, "cache root is inaccessible or linked", err)
			continue
		}
		resolved, err := filepath.EvalSymlinks(path)
		if err != nil {
			hostIssue(target, "host-cache", path, "cache root could not be resolved", err)
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
		hostIssue(target, "host-cache", path, "cache root is not a readable directory", err)
		return
	}
	entries, err := root.Open(".")
	if err != nil {
		_ = root.Close()
		hostIssue(target, "host-cache", path, "cache directory could not be enumerated", err)
		return
	}
	children, readErr := entries.ReadDir(hostEntryLimit + 1)
	_ = entries.Close()
	if readErr != nil || len(children) > hostEntryLimit {
		hostIssue(target, "host-cache", path, "cache directory entry limit or enumeration failure", readErr)
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
				hostIssue(target, "host-cache", filepath.Join(path, name), "archive is not a readable regular file", err)
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
			hostIssue(target, "host-cache", filepath.Join(path, marker), "cache marker is not bounded regular metadata", err)
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

var _ file.Resolver = (*hostFileResolver)(nil)
