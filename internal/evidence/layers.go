package evidence

import (
	"cmp"
	"encoding/json"
	"path"
	"slices"
	"strings"

	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/filetree/filenode"
	v1 "github.com/google/go-containerregistry/pkg/v1"
)

type layerCacheFile struct {
	path        string
	ref         file.Reference
	layer       int
	cacheRoot   string
	packagePath string
}

func cacheAncestor(p string, roots map[string]bool) string {
	for p != "/" && !roots[p] {
		p = path.Dir(p)
	}
	if roots[p] {
		return p
	}
	return ""
}

// Historical trees contain diff entries, not runtime visibility. Keep their
// reference identities until all confirmed cache contexts and final links are known.
func (c *imageCollector) collectLayers() error {
	const capability = "layer-retention"
	// Compressed descriptors come only from the raw manifest. Stereoscope's
	// Layer.Metadata.Digest is the uncompressed diffID and its Size is often zero.
	var manifest v1.Manifest
	if err := json.Unmarshal(c.loaded.Image.Metadata.RawManifest, &manifest); err != nil {
		c.issue(capability, "/", "verified layer manifest is unavailable")
		return nil
	}
	diffIDs := c.loaded.Image.Metadata.Config.RootFS.DiffIDs
	if len(manifest.Layers) != len(c.loaded.Image.Layers) || len(diffIDs) != len(c.loaded.Image.Layers) {
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
			record, valid := readRecord(data)
			if !valid {
				c.issue(capability, name, "invalid historical conda marker")
				return nil
			}
			if !marker && !toolingName(record.Name) {
				return nil
			}
			context := markers[name]
			if !marker {
				root = path.Join(path.Dir(path.Dir(name)), "pkgs")
			}
			context.root, context.packagePath = root, packagePath
			if context.refs == nil {
				context.refs = map[file.ID]bool{}
			}
			context.refs[node.Reference.ID()] = true
			markers[name] = context
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
			root := cacheAncestor(path.Dir(files[entry].path), activeRoots)
			if root == "" {
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
			if node.IsLink() && cacheAncestor(string(p), historicalRoots) == "" && c.cacheRelevantPath(string(p), historicalRoots) {
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
			if cacheAncestor(string(p), historicalRoots) == "" {
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
		archive := archivePath(entry.path) && entry.cacheRoot != "" && entry.cacheRoot == path.Dir(entry.path)
		if entry.packagePath == "" && !archive {
			continue
		}
		content, err := c.contentReference(entry.ref)
		if err != nil {
			if c.ctx.Err() != nil {
				return c.ctx.Err()
			}
			c.issue(capability, entry.path, err.Error())
			continue
		}
		key := groupKey{entry.layer, entry.packagePath}
		group := groups[key]
		group.runtime = group.runtime || !finalComplete || runtimeRefs[content.ID()]
		if finalRefs[content.ID()] {
			if entry.packagePath != "" {
				groups[key] = group
			}
			continue
		}
		metadata, metadataErr := c.loaded.Image.FileCatalog.Get(entry.ref)
		var size int64
		if metadataErr == nil && metadata.FileInfo != nil && metadata.Size() >= 0 {
			size = metadata.Size()
		} else {
			c.issue(capability, entry.path, "historical cache metadata is unavailable")
		}
		found, resolution, err := c.tree.File(file.Path(entry.path))
		if c.ctx.Err() != nil {
			return c.ctx.Err()
		}
		if err != nil && archive {
			c.issue(capability, entry.path, "final cache path cannot be inspected")
			continue
		}
		overwritten := err == nil && found && resolution != nil && resolution.HasReference() && resolution.ID() != entry.ref.ID()
		if entry.packagePath != "" {
			group.overwritten = group.overwritten || overwritten
			group.bytes += size
			if group.reference.ID() == 0 || entry.path < string(group.reference.RealPath) {
				group.reference = entry.ref
			}
			groups[key] = group
		}
		if archive {
			kind := "archive-hidden"
			if overwritten {
				kind = "archive-overwritten"
			}
			blob := manifest.Layers[entry.layer]
			c.add(capability, &c.target.Retained, Artifact{Path: entry.path, Kind: kind, Bytes: size, Layer: entry.layer, DiffID: diffIDs[entry.layer].String(), BlobDigest: blob.Digest.String(), LayerBytes: blob.Size, Reference: c.reference(entry.ref)})
		}
	}
	keys := make([]groupKey, 0, len(groups))
	for key := range groups {
		if err := c.ctx.Err(); err != nil {
			return err
		}
		keys = append(keys, key)
	}
	slices.SortFunc(keys, func(a, b groupKey) int {
		return cmp.Or(cmp.Compare(a.path, b.path), cmp.Compare(a.layer, b.layer))
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
		blob := manifest.Layers[key.layer]
		c.add(capability, &c.target.Retained, Artifact{Path: key.path, Kind: kind, Bytes: group.bytes, Layer: key.layer, DiffID: diffIDs[key.layer].String(), BlobDigest: blob.Digest.String(), LayerBytes: blob.Size, Reference: c.reference(group.reference)})
	}
	return c.ctx.Err()
}
