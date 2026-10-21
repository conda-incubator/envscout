package evidence

import (
	"archive/tar"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"

	"github.com/anaconda/envscout/internal/discovery"
	"github.com/anaconda/envscout/internal/imageinput"
	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/filetree"
	"github.com/anchore/stereoscope/pkg/filetree/filenode"
	"github.com/anchore/stereoscope/pkg/image"
)

const (
	imagePathLimit     = 500000
	imageEntryLimit    = 10000
	imageMetadataLimit = 1 << 20
)

var imageCapabilities = []string{"prefixes", "history", "tooling-prefix", "final-cache", "cache-link-dependencies", "runtime-config", "os-package-tools", "shell-tools", "layer-retention"}

type imageCollector struct {
	ctx      context.Context
	loaded   *imageinput.Loaded
	tree     filetree.Reader
	target   Target
	prefixes []Prefix
	caches   map[string]bool
	limited  map[string]bool
}

// CollectImage borrows an already verified image. Loading and cleanup belong to the caller.
func CollectImage(ctx context.Context, loaded *imageinput.Loaded, req Request) (Target, error) {
	target := Target{Kind: "oci-archive", Roots: []string{}, Prefixes: []Prefix{}, Archives: []Artifact{}, Extracted: []Artifact{}, Tools: []Artifact{}, Shells: []Artifact{}, Retained: []Artifact{}, Coverage: map[string]string{}, Issues: []Issue{}}
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
	c := imageCollector{ctx: ctx, loaded: loaded, tree: tree, target: target, prefixes: []Prefix{}, caches: map[string]bool{}, limited: map[string]bool{}}
	defer func() { c.sort() }()
	needsPrefixes := Requested(req, "prefixes") || Requested(req, "history") || Requested(req, "tooling-prefix") || Requested(req, "runtime-config")
	if needsPrefixes {
		discoveryImage := loaded.Image
		if !Requested(req, "history") {
			// Discovery also reads history by default. A borrowed view hides just
			// those entries so disabling history avoids its I/O, not only output.
			discoveryImage = &image.Image{Layers: []*image.Layer{{SquashedTree: withoutImageHistory{Reader: tree, ctx: ctx}}}, FileCatalog: loaded.Image.FileCatalog}
		}
		report, err := discovery.FindImageConda(ctx, discoveryImage)
		if err != nil {
			return c.target, err
		}
		for _, issue := range report.Issues {
			isCondaEvidence := strings.Contains(issue.Path, "/conda-meta") || strings.Contains(issue.Error, "conda") || strings.Contains(issue.Error, "discovery") || strings.Contains(issue.Error, "walk image")
			if !isCondaEvidence {
				continue
			}
			capability := "prefixes"
			if path.Base(issue.Path) == "history" {
				capability = "history"
			}
			c.issue(capability, issue.Path, issue.Error)
			if capability == "prefixes" {
				for _, dependent := range []string{"history", "tooling-prefix", "runtime-config"} {
					c.issue(dependent, issue.Path, "prefix discovery is incomplete")
				}
			}
		}
		for _, env := range report.Environments {
			if err := ctx.Err(); err != nil {
				return c.target, err
			}
			if len(c.prefixes) >= imageEntryLimit {
				for _, cap := range c.selected("prefixes", "history", "tooling-prefix", "runtime-config") {
					c.limit(cap, env.Path, "prefix entry limit exceeded (10000)")
				}
				break
			}
			prefix := Prefix{Path: env.Path}
			if Requested(req, "history") {
				prefix.Revision = env.Revision
			}
			c.prefixes = append(c.prefixes, prefix)
		}
	}
	needsCaches := Requested(req, "final-cache") || Requested(req, "cache-link-dependencies") || Requested(req, "layer-retention")
	if Requested(req, "tooling-prefix") || needsCaches {
		caps := c.selected("tooling-prefix", "final-cache", "cache-link-dependencies", "layer-retention")
		if err := c.collectMarkers(caps, needsCaches); err != nil {
			return c.target, err
		}
	}
	if Requested(req, "prefixes") || Requested(req, "history") || Requested(req, "tooling-prefix") {
		c.target.Prefixes = append(c.target.Prefixes, c.prefixes...)
		if !Requested(req, "tooling-prefix") {
			for i := range c.target.Prefixes {
				c.target.Prefixes[i].Tooling = false
			}
		}
	}
	if Requested(req, "final-cache") {
		if err := c.collectCache(); err != nil {
			return c.target, err
		}
	}
	if Requested(req, "cache-link-dependencies") {
		if err := c.collectCacheLinks(); err != nil {
			return c.target, err
		}
	}
	if Requested(req, "runtime-config") {
		if err := c.collectRuntime(req.RuntimePrefix); err != nil {
			return c.target, err
		}
	}
	for _, capability := range []string{"os-package-tools", "shell-tools"} {
		if Requested(req, capability) {
			if err := c.collectTools(capability); err != nil {
				return c.target, err
			}
		}
	}
	if Requested(req, "layer-retention") {
		if err := c.collectLayers(); err != nil {
			return c.target, err
		}
	}
	c.sort()
	return c.target, ctx.Err()
}

type withoutImageHistory struct {
	filetree.Reader
	ctx context.Context
}

func (tree withoutImageHistory) Walk(visit func(file.Path, filenode.FileNode) error, conditions *filetree.WalkConditions) error {
	bounded := *conditions
	visited, capped := 0, false
	bounded.ShouldTerminate = func(p file.Path, node filenode.FileNode) bool {
		if tree.ctx.Err() != nil {
			return true
		}
		if visited >= imagePathLimit {
			capped = true
			return true
		}
		return conditions.ShouldTerminate != nil && conditions.ShouldTerminate(p, node)
	}
	err := tree.Reader.Walk(func(p file.Path, node filenode.FileNode) error {
		if err := tree.ctx.Err(); err != nil {
			return err
		}
		visited++
		if path.Base(string(p)) == "history" && path.Base(path.Dir(string(p))) == "conda-meta" {
			return nil
		}
		return visit(p, node)
	}, &bounded)
	if tree.ctx.Err() != nil {
		return tree.ctx.Err()
	}
	if capped {
		return fmt.Errorf("image discovery exceeds %d visited paths", imagePathLimit)
	}
	return err
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

type condaRecord struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

func plausibleRecord(data []byte) (condaRecord, bool) {
	var record condaRecord
	if json.Unmarshal(data, &record) != nil || len(record.Name) == 0 || len(record.Name) > 256 || len(record.Version) == 0 || len(record.Version) > 256 {
		return record, false
	}
	for _, value := range []string{record.Name, record.Version} {
		for _, ch := range value {
			if ch <= ' ' || ch >= 127 || ch == '/' || ch == '\\' {
				return record, false
			}
		}
	}
	for _, ch := range record.Name {
		allowed := ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '-' || ch == '_' || ch == '.'
		if !allowed {
			return record, false
		}
	}
	return record, true
}

func toolingRecord(record condaRecord) bool {
	return record.Name == "conda" || record.Name == "mamba" || record.Name == "micromamba"
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

func (c *imageCollector) collectMarkers(capabilities []string, caches bool) error {
	visited, records := 0, 0
	return c.walk(c.tree, capabilities, &visited, func(p file.Path, node filenode.FileNode) error {
		name := string(p)
		isTooling := path.Base(path.Dir(name)) == "conda-meta" && path.Ext(name) == ".json"
		root, _, isCache := cacheMarker(name)
		if !isTooling && (!caches || !isCache) {
			return nil
		}
		caps := capabilities
		if !isTooling {
			caps = c.selected("final-cache", "cache-link-dependencies", "layer-retention")
		}
		if records >= imageEntryLimit {
			for _, cap := range caps {
				c.limit(cap, name, "metadata entry limit exceeded (10000)")
			}
			return nil
		}
		records++
		if node.FileType != file.TypeRegular || node.Reference == nil {
			for _, cap := range caps {
				c.issue(cap, name, "conda marker is not a regular file")
			}
			return nil
		}
		data, err := c.readReference(*node.Reference, imageMetadataLimit, true)
		if err != nil {
			if c.ctx.Err() != nil {
				return c.ctx.Err()
			}
			for _, cap := range caps {
				c.issue(cap, name, err.Error())
			}
			return nil
		}
		record, valid := plausibleRecord(data)
		if !valid {
			for _, cap := range caps {
				c.issue(cap, name, "invalid conda package marker")
			}
			return nil
		}
		if caches && isCache {
			c.caches[root] = true
		}
		if isTooling && toolingRecord(record) {
			prefix := path.Dir(path.Dir(name))
			if caches {
				c.caches[path.Join(prefix, "pkgs")] = true
			}
			for i := range c.prefixes {
				if c.prefixes[i].Path == prefix {
					c.prefixes[i].Tooling = true
				}
			}
		}
		return nil
	})
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
		if _, valid := plausibleRecord(data); !valid {
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
	sort.Slice(c.target.Prefixes, func(i, j int) bool { return c.target.Prefixes[i].Path < c.target.Prefixes[j].Path })
	for _, artifacts := range [][]Artifact{c.target.Archives, c.target.Extracted, c.target.Tools, c.target.Shells, c.target.Retained} {
		sort.Slice(artifacts, func(i, j int) bool {
			if artifacts[i].Path == artifacts[j].Path {
				return artifacts[i].Layer < artifacts[j].Layer
			}
			return artifacts[i].Path < artifacts[j].Path
		})
	}
	sort.Slice(c.target.Issues, func(i, j int) bool {
		a, b := c.target.Issues[i], c.target.Issues[j]
		if a.Capability != b.Capability {
			return a.Capability < b.Capability
		}
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		return a.Message < b.Message
	})
}
