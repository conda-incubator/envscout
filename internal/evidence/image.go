package evidence

import (
	"archive/tar"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"slices"
	"strings"

	"github.com/anaconda/envscout/internal/discovery"
	"github.com/anaconda/envscout/internal/imageinput"
	"github.com/anaconda/envscout/internal/inventory"
	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/filetree"
	"github.com/anchore/stereoscope/pkg/filetree/filenode"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

const (
	imagePathLimit     = 500000
	imageEntryLimit    = 10000
	imageMetadataLimit = 1 << 20
)

var imageCapabilities = []string{"prefixes", "history", "tooling-prefix", "final-cache", "cache-link-dependencies", "runtime-config", "os-package-tools", "shell-tools", "layer-retention"}

type imageCollector struct {
	ctx     context.Context
	loaded  *imageinput.Loaded
	tree    filetree.Reader
	target  Target
	caches  map[string]bool
	limited map[string]bool
	// records holds facts from the one final conda-meta parse, keyed by prefix. A prefix is
	// present only when at least one valid record was parsed for it.
	records map[string]*prefixRecords
	// confirmed holds every prefix with a valid final record. Runtime resolution reads it
	// even when the prefix capabilities are not exported.
	confirmed []Prefix
}

// prefixRecords is the parsed final-record facts for one prefix. Membership in the map is
// the validity signal; there is no separate flag.
type prefixRecords struct {
	tooling bool
	// cacheRoots are cache roots named by the record's ExtractedPackageDir or Link.Source
	// (parent directory), kept only when the root is a real directory in the final tree.
	cacheRoots []string
}

// CollectImage borrows an already verified image. Loading and cleanup belong to the caller.
// On cancellation it returns the partial target with every selected capability marked
// Partial, together with the context error. Positive evidence gathered before the cancel
// is kept.
func CollectImage(ctx context.Context, loaded *imageinput.Loaded, req Request) (target Target, err error) {
	target = Target{Kind: "oci-archive", Roots: []string{}, Prefixes: []Prefix{}, Archives: []Artifact{}, Extracted: []Artifact{}, Tools: []Artifact{}, Shells: []Artifact{}, Retained: []Artifact{}, Coverage: map[string]string{}, Issues: []Issue{}}
	for _, capability := range imageCapabilities {
		target.Coverage[capability] = NotCollected
		if Requested(req, capability) {
			target.Coverage[capability] = Complete
		}
	}
	if err := ctx.Err(); err != nil {
		return target, err
	}
	if loaded == nil || loaded.Image == nil || loaded.Image.FileCatalog == nil {
		return target, fmt.Errorf("a loaded image is required")
	}
	if len(loaded.Image.Layers) > 0 && loaded.Image.Layers[len(loaded.Image.Layers)-1] == nil {
		return target, fmt.Errorf("image has no final layer")
	}
	tree := loaded.Image.SquashedTree()
	if tree == nil {
		return target, fmt.Errorf("image has no final filesystem")
	}
	identity := loaded.Identity
	target.Input, target.Image = identity.Input, &identity
	target.ID = "oci:" + identity.ManifestDigest + "@" + identity.OS + "/" + identity.Architecture
	if identity.Variant != "" {
		target.ID += "/" + identity.Variant
	}
	c := imageCollector{ctx: ctx, loaded: loaded, tree: tree, target: target, caches: map[string]bool{}, limited: map[string]bool{}, records: map[string]*prefixRecords{}}
	defer func() {
		c.sort()
		target = c.target
		if err != nil || ctx.Err() != nil {
			err = errors.Join(err, c.cancelled(ctx))
		}
	}()
	err = c.run(req)
	return c.target, err
}

// cancelled marks every selected capability Partial when collection was cancelled, so a
// partial result can never report Complete. It returns the context cause, or nil.
func (c *imageCollector) cancelled(ctx context.Context) error {
	cause := ctx.Err()
	if cause == nil {
		return nil
	}
	for capability, coverage := range c.target.Coverage {
		if coverage != NotCollected {
			c.target.Coverage[capability] = Partial
		}
	}
	return cause
}

// run executes the requested phases in dependency order. Each phase returns on error or
// cancellation; the caller then reports partial coverage.
func (c *imageCollector) run(req Request) error {
	needsPrefixes := Requested(req, "prefixes") || Requested(req, "history") || Requested(req, "tooling-prefix") || Requested(req, "runtime-config")
	needsCaches := Requested(req, "final-cache") || Requested(req, "cache-link-dependencies") || Requested(req, "layer-retention")
	var candidates []discovery.Environment
	if needsPrefixes {
		report, err := discovery.FindImage(c.ctx, c.loaded.Image, Requested(req, "history"))
		if err != nil {
			return err
		}
		c.reportIssues(report.Issues)
		candidates = report.Environments
	}
	// Records are needed for prefix confirmation, tooling, cache roots, and layer tooling.
	// Tool and shell scans do not need them.
	var recordErr error
	if needsPrefixes || needsCaches {
		recordErr = c.parseFinalRecords()
	}
	if needsPrefixes {
		c.confirmPrefixes(req, candidates)
	}
	if recordErr != nil {
		return recordErr
	}
	for _, step := range []struct {
		enabled bool
		collect func() error
	}{
		{needsCaches, func() error { return c.collectMarkers(true) }},
		{Requested(req, "final-cache"), c.collectCache},
		{Requested(req, "cache-link-dependencies"), c.collectCacheLinks},
		{Requested(req, "runtime-config"), func() error { return c.collectRuntime(req.RuntimePrefix) }},
		{Requested(req, "os-package-tools"), func() error { return c.collectTools("os-package-tools") }},
		{Requested(req, "shell-tools"), func() error { return c.collectTools("shell-tools") }},
		{Requested(req, "layer-retention"), c.collectLayers},
	} {
		if step.enabled {
			if err := step.collect(); err != nil {
				return err
			}
		}
	}
	return c.ctx.Err()
}

// reportIssues routes discovery issues about conda evidence to the affected capabilities.
func (c *imageCollector) reportIssues(issues []discovery.Issue) {
	for _, issue := range issues {
		if path.Base(issue.Path) == "history" {
			c.issue("history", issue.Path, issue.Error)
			continue
		}
		for _, capability := range c.selected("prefixes", "history", "tooling-prefix", "runtime-config") {
			c.issue(capability, issue.Path, issue.Error)
		}
	}
}

// confirmPrefixes uses already parsed records only, so positives survive cancellation.
func (c *imageCollector) confirmPrefixes(req Request, candidates []discovery.Environment) {
	dependents := c.selected("prefixes", "history", "tooling-prefix", "runtime-config")
	for _, env := range candidates {
		entry, ok := c.records[env.Path]
		if !ok {
			for _, capability := range dependents {
				c.issue(capability, env.Path, "candidate prefix has no valid final conda record")
			}
			continue
		}
		if len(c.confirmed) >= imageEntryLimit {
			for _, capability := range dependents {
				c.limit(capability, env.Path, "prefix entry limit exceeded (10000)")
			}
			break
		}
		prefix := Prefix{Path: env.Path, Tooling: entry.tooling}
		if Requested(req, "history") {
			prefix.Revision = env.Revision
		}
		c.confirmed = append(c.confirmed, prefix)
		if Requested(req, "prefixes") || Requested(req, "history") || Requested(req, "tooling-prefix") {
			if !Requested(req, "tooling-prefix") {
				prefix.Tooling = false
			}
			c.target.Prefixes = append(c.target.Prefixes, prefix)
		}
	}
}

func (c *imageCollector) selected(caps ...string) []string {
	selected := []string{}
	for _, cap := range caps {
		if c.target.Coverage[cap] != NotCollected {
			selected = append(selected, cap)
		}
	}
	return selected
}

func (c *imageCollector) issue(capability, p, message string) {
	if c.target.Coverage[capability] == NotCollected {
		return
	}
	c.target.Coverage[capability] = Partial
	if len(c.target.Issues) < imageEntryLimit-len(imageCapabilities) {
		c.target.Issues = append(c.target.Issues, Issue{Capability: capability, Path: p, Message: message})
	} else if !c.limited["issues:"+capability] {
		c.limited["issues:"+capability] = true
		c.target.Issues = append(c.target.Issues, Issue{Capability: capability, Path: p, Message: "collection issue limit exceeded (10000)"})
	}
}

func (c *imageCollector) limit(capability, p, message string) {
	key := capability + ":" + message
	if !c.limited[key] {
		c.limited[key] = true
		c.issue(capability, p, message)
	}
}

func (c *imageCollector) add(capability string, artifacts *[]Artifact, artifact Artifact) {
	if len(*artifacts) >= imageEntryLimit {
		c.limit(capability, artifact.Path, "artifact entry limit exceeded (10000)")
		return
	}
	*artifacts = append(*artifacts, artifact)
}

func (c *imageCollector) walk(tree filetree.Reader, capabilities []string, visited *int, visit func(file.Path, filenode.FileNode) error) error {
	if tree == nil {
		for _, cap := range capabilities {
			c.issue(cap, "/", "filesystem tree is unavailable")
		}
		return nil
	}
	err := tree.Walk(func(p file.Path, node filenode.FileNode) error {
		if err := c.ctx.Err(); err != nil {
			return err
		}
		*visited++
		return visit(p, node)
	}, &filetree.WalkConditions{LinkOptions: []filetree.LinkResolutionOption{}, ShouldContinueBranch: func(_ file.Path, node filenode.FileNode) bool { return !node.IsLink() }, ShouldTerminate: func(p file.Path, _ filenode.FileNode) bool {
		if c.ctx.Err() != nil {
			return true
		}
		if *visited >= imagePathLimit {
			for _, cap := range capabilities {
				c.limit(cap, string(p), "filesystem traversal limit exceeded (500000 paths)")
			}
			return true
		}
		return false
	}})
	if c.ctx.Err() != nil {
		return c.ctx.Err()
	}
	if err != nil {
		for _, cap := range capabilities {
			c.issue(cap, "/", "filesystem traversal failed")
		}
	}
	return nil
}

// readRecord decodes one conda metadata document into the canonical Syft type. A record
// needs a non-empty name and version, the same rule inventory applies to final records.
func readRecord(data []byte) (pkg.CondaMetaPackage, bool) {
	var record pkg.CondaMetaPackage
	if json.Unmarshal(data, &record) != nil || record.Name == "" || record.Version == "" {
		return record, false
	}
	return record, true
}

// toolingName reports whether a parsed package is an installed conda tool.
func toolingName(name string) bool {
	return name == "conda" || name == "mamba" || name == "micromamba"
}

// cacheRootFromRecord maps a build-host extracted-package path to its parent cache root.
// The build-host path is only a hint: the root must be an absolute POSIX directory that
// exists in the final image, so an absent path never produces a collection issue.
func (c *imageCollector) cacheRootFromRecord(extracted string) (string, bool) {
	if extracted == "" || !path.IsAbs(extracted) || strings.ContainsAny(extracted, "\\\x00") {
		return "", false
	}
	root := path.Dir(path.Clean(extracted))
	if root == "/" {
		return "", false
	}
	node, ok := c.tree.TreeReader().Node(filenode.IDByPath(file.Path(root))).(*filenode.FileNode)
	if !ok || node.FileType != file.TypeDirectory {
		return "", false
	}
	return root, true
}

// parseFinalRecords runs the conda-only cataloger once over the final image. It is
// cancellation-safe: records Syft parsed before a cancel or parse error are still applied,
// and the context cause is returned for the caller to report.
func (c *imageCollector) parseFinalRecords() error {
	src := inventory.ImageSource(c.loaded.Image, c.loaded.Identity.Input)
	pkgs, err := inventory.CondaRecords(c.ctx, src, source.SquashedScope)
	for _, p := range pkgs {
		meta, ok := p.Metadata.(pkg.CondaMetaPackage)
		if !ok {
			continue
		}
		for _, location := range p.Locations.ToSlice() {
			real := location.RealPath
			// Syft follows links. Only a direct, non-alias conda-meta record establishes a prefix.
			if real != location.AccessPath || !strings.HasSuffix(real, ".json") || path.Base(path.Dir(real)) != "conda-meta" {
				continue
			}
			prefix := path.Dir(path.Dir(real))
			entry := c.records[prefix]
			if entry == nil {
				entry = &prefixRecords{}
				c.records[prefix] = entry
			}
			if toolingName(meta.Name) {
				entry.tooling = true
			}
			for _, extracted := range []string{meta.ExtractedPackageDir, linkSource(meta)} {
				if root, ok := c.cacheRootFromRecord(extracted); ok {
					entry.cacheRoots = append(entry.cacheRoots, root)
				}
			}
		}
	}
	if cerr := c.ctx.Err(); cerr != nil {
		return cerr
	}
	if err != nil {
		// Malformed or unparsable records are partial evidence, not a fatal error. Valid
		// records parsed alongside them stay positive.
		for _, capability := range c.selected("prefixes", "history", "tooling-prefix", "runtime-config", "final-cache", "layer-retention") {
			c.issue(capability, "/", fmt.Sprintf("final conda records are incomplete: %v", err))
		}
	}
	return nil
}

func linkSource(meta pkg.CondaMetaPackage) string {
	if meta.Link == nil {
		return ""
	}
	return meta.Link.Source
}

func (c *imageCollector) readReference(ref file.Reference, limit int64, whole bool) ([]byte, error) {
	if err := c.ctx.Err(); err != nil {
		return nil, err
	}
	metadata, err := c.loaded.Image.FileCatalog.Get(ref)
	if err != nil {
		return nil, fmt.Errorf("file metadata is unavailable")
	}
	if metadata.FileInfo == nil || metadata.Type != file.TypeRegular || !metadata.Mode().IsRegular() || metadata.Size() < 0 {
		return nil, fmt.Errorf("evidence is not a regular file")
	}
	if whole && metadata.Size() > limit {
		return nil, fmt.Errorf("metadata exceeds %d bytes", limit)
	}
	reader, err := c.loaded.Image.OpenReference(ref)
	if err != nil {
		return nil, fmt.Errorf("file content is unavailable")
	}
	maxRead := limit
	if whole {
		maxRead++
	}
	data, readErr := io.ReadAll(io.LimitReader(evidenceContextReader{c.ctx, reader}, maxRead))
	closeErr := reader.Close()
	if err := c.ctx.Err(); err != nil {
		return nil, err
	}
	if readErr != nil || closeErr != nil {
		return nil, fmt.Errorf("file content could not be read")
	}
	if whole && int64(len(data)) > limit {
		return nil, fmt.Errorf("metadata exceeds %d bytes", limit)
	}
	return data, nil
}

type evidenceContextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r evidenceContextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}

// cacheMarker classifies a standalone info/index.json marker. Site-packages and conda-meta
// are never cache markers.
func cacheMarker(p string) (string, string, bool) {
	if !strings.HasSuffix(p, "/info/index.json") || strings.Contains(p, "/site-packages/") || strings.Contains(p, "/conda-meta/") {
		return "", "", false
	}
	packagePath := path.Dir(path.Dir(p))
	root := path.Dir(packagePath)
	if root == "/" || packagePath == "/" {
		return "", "", false
	}
	return root, packagePath, true
}

// collectMarkers records tooling-derived and standalone cache roots. Conda-meta records were
// parsed once by parseFinalRecords and are not read again. Standalone info/index markers
// are found by a targeted glob, not a full tree walk.
func (c *imageCollector) collectMarkers(caches bool) error {
	if caches {
		for prefix, entry := range c.records {
			if entry.tooling {
				c.caches[path.Join(prefix, "pkgs")] = true
			}
			for _, root := range entry.cacheRoots {
				c.caches[root] = true
			}
		}
	}
	if !caches {
		return nil
	}
	searcher := c.loaded.Image.SquashedSearchContext
	if searcher == nil {
		searcher = filetree.NewSearchContext(c.tree, c.loaded.Image.FileCatalog)
	}
	refs, err := searcher.SearchByGlob("**/info/index.json")
	if err := c.ctx.Err(); err != nil {
		return err
	}
	caps := c.selected("final-cache", "cache-link-dependencies", "layer-retention")
	if err != nil {
		for _, capability := range caps {
			c.issue(capability, "/", fmt.Sprintf("search cache markers: %v", err))
		}
		return nil
	}
	markers := 0
	for _, res := range refs {
		if err := c.ctx.Err(); err != nil {
			return err
		}
		name := string(res.RequestPath)
		root, _, isCache := cacheMarker(name)
		if !isCache {
			continue
		}
		if markers >= imageEntryLimit {
			for _, capability := range caps {
				c.limit(capability, name, "metadata entry limit exceeded (10000)")
			}
			break
		}
		markers++
		if res.Reference == nil || string(res.RealPath) != name {
			for _, capability := range caps {
				c.issue(capability, name, "conda marker is not a regular file")
			}
			continue
		}
		data, err := c.readReference(*res.Reference, imageMetadataLimit, true)
		if err != nil {
			if c.ctx.Err() != nil {
				return c.ctx.Err()
			}
			for _, capability := range caps {
				c.issue(capability, name, err.Error())
			}
			continue
		}
		if _, valid := readRecord(data); !valid {
			for _, capability := range caps {
				c.issue(capability, name, "invalid conda package marker")
			}
			continue
		}
		c.caches[root] = true
	}
	return c.ctx.Err()
}

func within(p, root string) bool {
	return p == root || strings.HasPrefix(p, strings.TrimSuffix(root, "/")+"/")
}
func (c *imageCollector) inCache(p string) bool {
	for {
		if c.ctx.Err() != nil {
			return false
		}
		if c.caches[p] {
			return true
		}
		if p == "/" || p == "." {
			return false
		}
		p = path.Dir(p)
	}
}
func archivePath(p string) bool {
	return strings.HasSuffix(p, ".conda") || strings.HasSuffix(p, ".tar.bz2")
}
func (c *imageCollector) reference(ref file.Reference) string {
	layer := c.loaded.Image.FileCatalog.Layer(ref)
	if layer == nil {
		return string(ref.RealPath)
	}
	return fmt.Sprintf("%d:%s:%s", layer.Metadata.Index, layer.Metadata.Digest, ref.RealPath)
}

// Adopted hardlinks retain an old opener, not their original inode reference.
// Even a same-layer lookup is unsafe: duplicate tar paths reuse the reference
// and replace its opener. The public catalog cannot prove that shared identity.
func (c *imageCollector) contentReference(ref file.Reference) (file.Reference, error) {
	if err := c.ctx.Err(); err != nil {
		return ref, err
	}
	metadata, err := c.loaded.Image.FileCatalog.Get(ref)
	if err != nil || metadata.FileInfo == nil {
		return ref, fmt.Errorf("content identity metadata is unavailable")
	}
	if header, ok := metadata.Sys().(*tar.Header); ok && header.Typeflag == tar.TypeLink {
		return ref, fmt.Errorf("original hardlink content identity is unavailable")
	}
	return ref, nil
}

func (c *imageCollector) cacheRelevantReference(ref file.Reference, roots map[string]bool) bool {
	if len(roots) == 0 {
		return false
	}
	// An overwritten intermediate alias also loses its old binding. Only a
	// source diff with no cache paths can prove an adopted hardlink irrelevant.
	layer := c.loaded.Image.FileCatalog.Layer(ref)
	if layer == nil || layer.Tree == nil {
		return true
	}
	for root := range roots {
		if c.ctx.Err() != nil {
			return true
		}
		found, _, err := layer.Tree.File(file.Path(root))
		if err != nil || found {
			return true
		}
	}
	return false
}

func (c *imageCollector) collectCache() error {
	visited, markers := 0, 0
	packages := map[string]int{}
	var files []struct {
		path string
		ref  file.Reference
	}
	err := c.walk(c.tree, []string{"final-cache"}, &visited, func(p file.Path, node filenode.FileNode) error {
		name := string(p)
		if !c.inCache(name) {
			return nil
		}
		if node.FileType == file.TypeRegular && node.Reference != nil {
			files = append(files, struct {
				path string
				ref  file.Reference
			}{name, *node.Reference})
			if archivePath(name) && c.caches[path.Dir(name)] {
				metadata, err := c.loaded.Image.FileCatalog.Get(*node.Reference)
				if err != nil || metadata.FileInfo == nil || metadata.Size() < 0 {
					c.issue("final-cache", name, "archive metadata is unavailable")
					return nil
				}
				c.add("final-cache", &c.target.Archives, Artifact{Path: name, Kind: "archive", Bytes: metadata.Size(), Reference: c.reference(*node.Reference)})
			}
		}
		root, packagePath, marker := cacheMarker(name)
		if !marker || !c.caches[root] {
			return nil
		}
		if markers >= imageEntryLimit {
			c.limit("final-cache", name, "metadata entry limit exceeded (10000)")
			return nil
		}
		markers++
		if node.FileType != file.TypeRegular || node.Reference == nil {
			c.issue("final-cache", name, "extracted cache marker is not a regular file")
			return nil
		}
		data, err := c.readReference(*node.Reference, imageMetadataLimit, true)
		if err != nil {
			if c.ctx.Err() != nil {
				return c.ctx.Err()
			}
			c.issue("final-cache", name, err.Error())
			return nil
		}
		if _, valid := readRecord(data); !valid {
			c.issue("final-cache", name, "invalid extracted cache marker")
			return nil
		}
		if len(c.target.Extracted) < imageEntryLimit {
			packages[packagePath] = len(c.target.Extracted)
		}
		c.add("final-cache", &c.target.Extracted, Artifact{Path: packagePath, Kind: "extracted", Reference: c.reference(*node.Reference)})
		return nil
	})
	if err != nil {
		return err
	}
	for _, entry := range files {
		if err := c.ctx.Err(); err != nil {
			return err
		}
		root := path.Dir(entry.path)
		for !c.caches[root] && root != "/" {
			if err := c.ctx.Err(); err != nil {
				return err
			}
			root = path.Dir(root)
		}
		rel := strings.TrimPrefix(entry.path, root+"/")
		packagePath := path.Join(root, strings.SplitN(rel, "/", 2)[0])
		if index, ok := packages[packagePath]; ok {
			metadata, err := c.loaded.Image.FileCatalog.Get(entry.ref)
			if err != nil || metadata.FileInfo == nil || metadata.Size() < 0 {
				c.issue("final-cache", entry.path, "cache file metadata is unavailable")
				continue
			}
			c.target.Extracted[index].Bytes += metadata.Size()
		}
	}
	return nil
}

func (c *imageCollector) resolve(p string) (*file.Resolution, error) {
	if err := c.ctx.Err(); err != nil {
		return nil, err
	}
	found, resolution, err := c.tree.File(file.Path(p), filetree.FollowBasenameLinks)
	if c.ctx.Err() != nil {
		return nil, c.ctx.Err()
	}
	if err != nil {
		return nil, fmt.Errorf("image-local link cannot be resolved")
	}
	if !found || resolution == nil {
		return nil, errors.New("image-local target is missing")
	}
	return resolution, nil
}

// Synthetic directories have no Reference (and hence no Resolution.RealPath).
// Resolve just their path via exact image nodes, then verify descendant refs
// using File. This never opens a host path or trusts a textual destination alone.
func (c *imageCollector) resolvedPath(p string) (string, error) {
	p = path.Clean(p)
	for depth := 0; depth < 128; depth++ {
		if err := c.ctx.Err(); err != nil {
			return "", err
		}
		parts := strings.Split(strings.TrimPrefix(p, "/"), "/")
		current, changed := "", false
		for index, part := range parts {
			if err := c.ctx.Err(); err != nil {
				return "", err
			}
			current += "/" + part
			raw := c.tree.TreeReader().Node(filenode.IDByPath(file.Path(current)))
			node, ok := raw.(*filenode.FileNode)
			if !ok {
				return "", fmt.Errorf("image-local target is missing")
			}
			if !node.IsLink() {
				continue
			}
			if node.LinkPath == "" {
				return "", fmt.Errorf("image-local link is malformed")
			}
			destination := string(node.LinkPath)
			if !path.IsAbs(destination) {
				destination = path.Join(path.Dir(current), destination)
			}
			p = path.Join(destination, strings.Join(parts[index+1:], "/"))
			changed = true
			break
		}
		if !changed {
			return p, nil
		}
	}
	return "", fmt.Errorf("image-local link resolution limit exceeded")
}

func (c *imageCollector) cacheRelevantPath(p string, roots map[string]bool) bool {
	p = path.Clean(p)
	for depth := 0; depth < 128; depth++ {
		if c.ctx.Err() != nil {
			return true
		}
		parts := strings.Split(strings.TrimPrefix(p, "/"), "/")
		current, changed := "", false
		for index, part := range parts {
			if c.ctx.Err() != nil {
				return true
			}
			current += "/" + part
			if roots[current] {
				return true
			}
			raw := c.tree.TreeReader().Node(filenode.IDByPath(file.Path(current)))
			node, ok := raw.(*filenode.FileNode)
			if !ok {
				return false
			}
			if !node.IsLink() {
				continue
			}
			destination := string(node.LinkPath)
			if !path.IsAbs(destination) {
				destination = path.Join(path.Dir(current), destination)
			}
			p = path.Join(destination, strings.Join(parts[index+1:], "/"))
			changed = true
			break
		}
		if !changed {
			return false
		}
	}
	return false
}

func (c *imageCollector) collectCacheLinks() error {
	visited := 0
	refs := map[file.ID]file.Reference{}
	cachePaths := map[string]file.Reference{}
	outside := map[file.ID]bool{}
	links := []struct {
		path string
		node filenode.FileNode
	}{}
	err := c.walk(c.tree, []string{"cache-link-dependencies"}, &visited, func(p file.Path, node filenode.FileNode) error {
		if node.FileType == file.TypeRegular && node.Reference != nil {
			content, err := c.contentReference(*node.Reference)
			if err != nil {
				if c.ctx.Err() != nil {
					return c.ctx.Err()
				}
				if c.cacheRelevantReference(*node.Reference, c.caches) {
					c.issue("cache-link-dependencies", string(p), err.Error())
				}
				return nil
			}
			if c.inCache(string(p)) {
				refs[content.ID()] = content
				cachePaths[string(p)] = content
			} else {
				outside[content.ID()] = true
			}
		}
		if node.IsLink() {
			if c.inCache(string(p)) {
				resolution, err := c.resolve(string(p))
				if err != nil {
					if c.ctx.Err() != nil {
						return c.ctx.Err()
					}
					// A dangling cache-only symlink cannot itself be a surviving
					// runtime reference; outside aliases are checked separately.
				} else if resolution.HasReference() {
					metadata, err := c.loaded.Image.FileCatalog.Get(*resolution.Reference)
					if err != nil || metadata.FileInfo == nil {
						c.issue("cache-link-dependencies", string(p), "cache link metadata is unavailable")
					} else if metadata.Type == file.TypeRegular {
						content, err := c.contentReference(*resolution.Reference)
						if err != nil {
							if c.ctx.Err() != nil {
								return c.ctx.Err()
							}
							c.issue("cache-link-dependencies", string(p), err.Error())
						} else {
							refs[content.ID()] = content
							cachePaths[string(p)] = content
						}
					}
				}
			}
			links = append(links, struct {
				path string
				node filenode.FileNode
			}{string(p), node})
		}
		return nil
	})
	if err != nil {
		return err
	}
	for id := range outside {
		if err := c.ctx.Err(); err != nil {
			return err
		}
		if _, ok := refs[id]; ok {
			c.target.CacheLinked = true
		}
	}
	probes := 0
	for _, link := range links {
		if err := c.ctx.Err(); err != nil {
			return err
		}
		resolution, err := c.resolve(link.path)
		if err != nil {
			if c.ctx.Err() != nil {
				return c.ctx.Err()
			}
			if !c.inCache(link.path) && (c.cacheRelevantPath(link.path, c.caches) || link.node.FileType == file.TypeHardLink) {
				c.issue("cache-link-dependencies", link.path, err.Error())
			}
			continue
		}
		isDirectory := !resolution.HasReference()
		if resolution.HasReference() {
			metadata, err := c.loaded.Image.FileCatalog.Get(*resolution.Reference)
			if err != nil || metadata.FileInfo == nil {
				c.issue("cache-link-dependencies", link.path, "resolved link metadata is unavailable")
				continue
			}
			isDirectory = metadata.Type == file.TypeDirectory
		}
		if !c.inCache(link.path) && resolution.HasReference() && !isDirectory {
			content, err := c.contentReference(*resolution.Reference)
			if err != nil {
				if c.ctx.Err() != nil {
					return c.ctx.Err()
				}
				if c.cacheRelevantReference(*resolution.Reference, c.caches) {
					c.issue("cache-link-dependencies", link.path, err.Error())
				}
				continue
			}
			_, cachedReference := refs[content.ID()]
			if cachedReference || c.inCache(string(resolution.RealPath)) {
				c.target.CacheLinked = true
			}
		}
		if isDirectory && link.node.FileType == file.TypeSymLink && !c.inCache(link.path) {
			destination, err := c.resolvedPath(link.path)
			if err != nil {
				if c.ctx.Err() != nil {
					return c.ctx.Err()
				}
				c.issue("cache-link-dependencies", link.path, err.Error())
				continue
			}
			if resolution.HasReference() {
				destination = string(resolution.RealPath)
			}
			for cachedPath, ref := range cachePaths {
				if err := c.ctx.Err(); err != nil {
					return err
				}
				if probes >= imagePathLimit {
					c.limit("cache-link-dependencies", link.path, "link reference limit exceeded (500000)")
					return nil
				}
				probes++
				if within(cachedPath, destination) {
					probe, err := c.resolve(path.Join(link.path, strings.TrimPrefix(cachedPath, destination)))
					if err != nil {
						if c.ctx.Err() != nil {
							return c.ctx.Err()
						}
						c.issue("cache-link-dependencies", link.path, "cache descendant link cannot be resolved")
						continue
					}
					if err == nil && probe.HasReference() {
						content, err := c.contentReference(*probe.Reference)
						if err == nil && content.ID() == ref.ID() {
							c.target.CacheLinked = true
							break
						}
					}
				}
			}
		}
	}
	return nil
}

func (c *imageCollector) sort() {
	slices.SortFunc(c.target.Prefixes, func(a, b Prefix) int { return cmp.Compare(a.Path, b.Path) })
	for _, artifacts := range [][]Artifact{c.target.Archives, c.target.Extracted, c.target.Tools, c.target.Shells, c.target.Retained} {
		slices.SortFunc(artifacts, func(a, b Artifact) int {
			return cmp.Or(cmp.Compare(a.Path, b.Path), cmp.Compare(a.Layer, b.Layer))
		})
	}
	slices.SortFunc(c.target.Issues, func(a, b Issue) int {
		return cmp.Or(cmp.Compare(a.Capability, b.Capability), cmp.Compare(a.Path, b.Path), cmp.Compare(a.Message, b.Message))
	})
}
