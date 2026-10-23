package evidence

import (
	"path"
	"sort"
	"strings"

	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/filetree/filenode"
)

type layerCacheFile struct {
	path        string
	ref         file.Reference
	layer       int
	cacheRoot   string
	packagePath string
}

// Historical trees contain diff entries, not runtime visibility. Keep their
// reference identities until all confirmed cache contexts and final links are known.
func (c *imageCollector) collectLayers() error {
	const capability = "layer-retention"
	if c.loaded.Manifest == nil || c.loaded.Config == nil {
		c.issue(capability, "/", "verified layer manifest/config descriptors are unavailable")
		return nil
	}
	if len(c.loaded.Manifest.Layers) != len(c.loaded.Image.Layers) || len(c.loaded.Config.RootFS.DiffIDs) != len(c.loaded.Image.Layers) {
		c.issue(capability, "/", "verified layer descriptors do not match loaded layers")
		return nil
	}
	visited, records := 0, 0
	files := []layerCacheFile{}
	type markerContext struct {
		root, packagePath string
		refs              map[file.ID]bool
	}
	markers := map[string]markerContext{}
	historicalRoots := map[string]bool{}
	for index, layer := range c.loaded.Image.Layers {
		if err := c.ctx.Err(); err != nil {
			return err
		}
		if layer == nil {
			c.issue(capability, "/", "layer tree is unavailable")
			continue
		}
		if visited >= imagePathLimit {
			c.limit(capability, "/", "filesystem traversal limit exceeded (500000 paths)")
			break
		}
		start := len(files)
		err := c.walk(layer.Tree, []string{capability}, &visited, func(p file.Path, node filenode.FileNode) error {
			name := string(p)
			if strings.HasPrefix(path.Base(name), ".wh.") {
				return nil
			}
			if node.FileType != file.TypeRegular || node.Reference == nil {
				return nil
			}
			files = append(files, layerCacheFile{path: name, ref: *node.Reference, layer: index})
			root, packagePath, marker := cacheMarker(name)
			tooling := path.Base(path.Dir(name)) == "conda-meta" && path.Ext(name) == ".json"
			if !marker && !tooling {
				return nil
			}
			if records >= imageEntryLimit {
				c.limit(capability, name, "metadata entry limit exceeded (10000)")
				return nil
			}
			records++
			data, err := c.readReference(*node.Reference, imageMetadataLimit, true)
			if err != nil {
				if c.ctx.Err() != nil {
					return c.ctx.Err()
				}
				c.issue(capability, name, err.Error())
				return nil
			}
			record, valid := plausibleRecord(data)
			if !valid {
				c.issue(capability, name, "invalid historical conda marker")
				return nil
			}
			if marker {
				context := markers[name]
				context.root, context.packagePath = root, packagePath
				if context.refs == nil {
					context.refs = map[file.ID]bool{}
				}
				context.refs[node.Reference.ID()] = true
				markers[name] = context
			} else if toolingRecord(record) {
				context := markers[name]
				context.root = path.Join(path.Dir(path.Dir(name)), "pkgs")
				if context.refs == nil {
					context.refs = map[file.ID]bool{}
				}
				context.refs[node.Reference.ID()] = true
				markers[name] = context
			}
			return nil
		})
		if err != nil {
			return err
		}
		activeRoots, activePackages := map[string]bool{}, map[string]bool{}
		for marker, context := range markers {
			if err := c.ctx.Err(); err != nil {
				return err
			}
			if layer.SquashedTree == nil {
				c.issue(capability, "/", "layer snapshot is unavailable")
				break
			}
			raw := layer.SquashedTree.TreeReader().Node(filenode.IDByPath(file.Path(marker)))
			node, ok := raw.(*filenode.FileNode)
			if !ok || node.FileType != file.TypeRegular || node.Reference == nil || !context.refs[node.Reference.ID()] {
				continue
			}
			activeRoots[context.root] = true
			historicalRoots[context.root] = true
			if context.packagePath != "" {
				activePackages[context.packagePath] = true
			}
		}
		for entry := start; entry < len(files); entry++ {
			if err := c.ctx.Err(); err != nil {
				return err
			}
			root := path.Dir(files[entry].path)
			for !activeRoots[root] && root != "/" {
				if err := c.ctx.Err(); err != nil {
					return err
				}
				root = path.Dir(root)
			}
			if !activeRoots[root] {
				continue
			}
			files[entry].cacheRoot = root
			relative := strings.TrimPrefix(files[entry].path, root+"/")
			packagePath := path.Join(root, strings.SplitN(relative, "/", 2)[0])
			if activePackages[packagePath] {
				files[entry].packagePath = packagePath
			}
		}
	}
	finalRefs, runtimeRefs := map[file.ID]bool{}, map[file.ID]bool{}
	finalVisited, finalComplete := 0, true
	if err := c.walk(c.tree, []string{capability}, &finalVisited, func(p file.Path, node filenode.FileNode) error {
		if node.FileType == file.TypeDirectory {
			return nil
		}
		resolution, err := c.resolve(string(p))
		if err != nil {
			if c.ctx.Err() != nil {
				return c.ctx.Err()
			}
			root := string(p)
			for !historicalRoots[root] && root != "/" {
				if c.ctx.Err() != nil {
					return c.ctx.Err()
				}
				root = path.Dir(root)
			}
			if node.IsLink() && !historicalRoots[root] && c.cacheRelevantPath(string(p), historicalRoots) {
				c.issue(capability, string(p), err.Error())
				finalComplete = false
			}
			return nil
		}
		if resolution.HasReference() {
			finalRefs[resolution.ID()] = true
			content, err := c.contentReference(*resolution.Reference)
			if err != nil {
				if c.ctx.Err() != nil {
					return c.ctx.Err()
				}
				if c.cacheRelevantReference(*resolution.Reference, historicalRoots) {
					c.issue(capability, string(p), err.Error())
					finalComplete = false
				}
				return nil
			}
			finalRefs[content.ID()] = true
			root := string(p)
			for !historicalRoots[root] && root != "/" {
				if err := c.ctx.Err(); err != nil {
					return err
				}
				root = path.Dir(root)
			}
			if !historicalRoots[root] {
				runtimeRefs[content.ID()] = true
			}
		}
		return nil
	}); err != nil {
		return err
	}
	if finalVisited >= imagePathLimit {
		return nil
	}
	// Group once by package and source layer; a quadratic per-package full-tree
	// scan would be unbounded work even with a bounded number of paths.
	type groupKey struct {
		layer int
		path  string
	}
	type groupSize struct {
		bytes       int64
		runtime     bool
		overwritten bool
		reference   file.Reference
	}
	groups := map[groupKey]groupSize{}
	for _, entry := range files {
		if err := c.ctx.Err(); err != nil {
			return err
		}
		key := groupKey{entry.layer, entry.packagePath}
		if entry.packagePath == "" {
			continue
		}
		group := groups[key]
		if !finalComplete {
			group.runtime = true
		}
		content, err := c.contentReference(entry.ref)
		if err != nil {
			if c.ctx.Err() != nil {
				return c.ctx.Err()
			}
			c.issue(capability, entry.path, err.Error())
			continue
		}
		if runtimeRefs[content.ID()] {
			group.runtime = true
		}
		if !finalRefs[content.ID()] {
			found, resolution, err := c.tree.File(file.Path(entry.path))
			if c.ctx.Err() != nil {
				return c.ctx.Err()
			}
			if err == nil && found && resolution != nil && resolution.HasReference() && resolution.ID() != entry.ref.ID() {
				group.overwritten = true
			}
			metadata, err := c.loaded.Image.FileCatalog.Get(entry.ref)
			if err == nil && metadata.FileInfo != nil && metadata.Size() >= 0 {
				group.bytes += metadata.Size()
				if group.reference.ID() == 0 || entry.path < string(group.reference.RealPath) {
					group.reference = entry.ref
				}
			} else {
				c.issue(capability, entry.path, "historical cache metadata is unavailable")
			}
		}
		groups[key] = group
	}
	for _, entry := range files {
		if err := c.ctx.Err(); err != nil {
			return err
		}
		content, err := c.contentReference(entry.ref)
		if err != nil {
			if c.ctx.Err() != nil {
				return c.ctx.Err()
			}
			continue
		}
		if finalRefs[content.ID()] {
			continue
		}
		kind, artifactPath := "", entry.path
		var size int64
		if archivePath(entry.path) && entry.cacheRoot != "" && entry.cacheRoot == path.Dir(entry.path) {
			kind = "archive"
			metadata, err := c.loaded.Image.FileCatalog.Get(entry.ref)
			if err == nil && metadata.FileInfo != nil && metadata.Size() >= 0 {
				size = metadata.Size()
			} else {
				c.issue(capability, entry.path, "historical archive metadata is unavailable")
			}
		}
		if kind == "" {
			continue
		}
		found, resolution, err := c.tree.File(file.Path(entry.path))
		if c.ctx.Err() != nil {
			return c.ctx.Err()
		}
		if err != nil {
			c.issue(capability, entry.path, "final cache path cannot be inspected")
			continue
		}
		overwritten := found && resolution != nil && resolution.HasReference() && resolution.ID() != entry.ref.ID()
		if overwritten {
			kind += "-overwritten"
		} else {
			kind += "-hidden"
		}
		blob := c.loaded.Manifest.Layers[entry.layer]
		c.add(capability, &c.target.Retained, Artifact{Path: artifactPath, Kind: kind, Bytes: size, Layer: entry.layer, DiffID: c.loaded.Config.RootFS.DiffIDs[entry.layer].String(), BlobDigest: blob.Digest.String(), LayerBytes: blob.Size, Reference: c.reference(entry.ref)})
	}
	keys := make([]groupKey, 0, len(groups))
	for key := range groups {
		if err := c.ctx.Err(); err != nil {
			return err
		}
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].path == keys[j].path {
			return keys[i].layer < keys[j].layer
		}
		return keys[i].path < keys[j].path
	})
	for _, key := range keys {
		if err := c.ctx.Err(); err != nil {
			return err
		}
		group := groups[key]
		if group.runtime || group.bytes == 0 {
			continue
		}
		kind := "extracted-hidden"
		if group.overwritten {
			kind = "extracted-overwritten"
		}
		blob := c.loaded.Manifest.Layers[key.layer]
		c.add(capability, &c.target.Retained, Artifact{Path: key.path, Kind: kind, Bytes: group.bytes, Layer: key.layer, DiffID: c.loaded.Config.RootFS.DiffIDs[key.layer].String(), BlobDigest: blob.Digest.String(), LayerBytes: blob.Size, Reference: c.reference(group.reference)})
	}
	return c.ctx.Err()
}
