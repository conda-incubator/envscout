package evidence

import (
	"archive/tar"
	"errors"
	"fmt"
	"path"
	"strings"

	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/filetree"
	"github.com/anchore/stereoscope/pkg/filetree/filenode"
)

func (c *imageCollector) reference(ref file.Reference) string {
	layer := c.loaded.Image.FileCatalog.Layer(ref)
	if layer == nil {
		return string(ref.RealPath)
	}
	return fmt.Sprintf("%d:%s:%s", layer.Metadata.Index, layer.Metadata.Digest, ref.RealPath)
}

// Adopted hardlinks retain an old opener, not their original inode reference.
// A later target-path lookup cannot prove the original shared inode binding,
// even within the same layer. The public catalog cannot recover that identity.
func (c *imageCollector) requireContentIdentity(ref file.Reference) error {
	if err := c.ctx.Err(); err != nil {
		return err
	}
	metadata, err := c.loaded.Image.FileCatalog.Get(ref)
	if err != nil || metadata.FileInfo == nil {
		return fmt.Errorf("content identity metadata is unavailable")
	}
	if header, ok := metadata.Sys().(*tar.Header); ok && header.Typeflag == tar.TypeLink {
		return fmt.Errorf("original hardlink content identity is unavailable")
	}
	return nil
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

func (c *imageCollector) resolveReference(p string) (*file.Reference, error) {
	if err := c.ctx.Err(); err != nil {
		return nil, err
	}
	ref, cached := c.resolvedReferences[p]
	var resolution *file.Resolution
	var found bool
	var err error
	if !cached {
		found, resolution, err = c.tree.File(file.Path(p), filetree.FollowBasenameLinks)
	}
	if c.ctx.Err() != nil {
		return nil, c.ctx.Err()
	}
	if cached {
		if ref == nil {
			return nil, nil
		}
		copy := *ref
		return &copy, nil
	}
	if err != nil {
		return nil, fmt.Errorf("image-local link cannot be resolved")
	}
	if !found || resolution == nil {
		return nil, errors.New("image-local target is missing")
	}
	ref = resolution.Reference
	// Direct non-link lookups are already cheap and need no retained state.
	linked := ref == nil || len(resolution.LinkResolutions) > 0 || resolution.RequestPath != ref.RealPath
	if linked && len(c.resolvedReferences) < imageEntryLimit && len(p) <= imageResolutionBytesLimit-c.resolvedReferenceBytes {
		bytes := len(p)
		if ref != nil {
			if len(ref.RealPath) > imageResolutionBytesLimit-c.resolvedReferenceBytes-bytes {
				return ref, nil
			}
			bytes += len(ref.RealPath)
			copy := *ref
			copy.RealPath = file.Path(strings.Clone(string(ref.RealPath)))
			ref = &copy
		}
		if c.resolvedReferences == nil {
			c.resolvedReferences = map[string]*file.Reference{}
		}
		c.resolvedReferences[strings.Clone(p)] = ref
		c.resolvedReferenceBytes += bytes
		if ref != nil {
			copy := *ref
			return &copy, nil
		}
	}
	return ref, nil
}

// Synthetic directories have no Reference (and hence no Resolution.RealPath).
// Resolve just their path via exact image nodes, then verify descendant refs
// using File. This never opens a host path or trusts a textual destination alone.
func (c *imageCollector) resolvedPath(p string) (string, error) {
	resolved, _, err := c.walkImagePath(p, imagePathResolution, nil)
	return resolved, err
}

func (c *imageCollector) cacheRelevantPath(p string, roots map[string]bool) bool {
	_, relevant, _ := c.walkImagePath(p, imagePathCacheRelevance, roots)
	return relevant
}

type imagePathPolicy uint8

const (
	imagePathResolution imagePathPolicy = iota
	imagePathCacheRelevance
)

// Relevance checks roots before node existence and follows even empty link
// destinations. Resolution instead requires every component and a nonempty link.
func (c *imageCollector) walkImagePath(p string, policy imagePathPolicy, roots map[string]bool) (string, bool, error) {
	p = path.Clean(p)
	for depth := 0; depth < 128; depth++ {
		if err := c.ctx.Err(); err != nil {
			return "", policy == imagePathCacheRelevance, err
		}
		parts := strings.Split(strings.TrimPrefix(p, "/"), "/")
		current, changed := "", false
		for index, part := range parts {
			if err := c.ctx.Err(); err != nil {
				return "", policy == imagePathCacheRelevance, err
			}
			current += "/" + part
			if policy == imagePathCacheRelevance && roots[current] {
				return "", true, nil
			}
			raw := c.tree.TreeReader().Node(filenode.IDByPath(file.Path(current)))
			node, ok := raw.(*filenode.FileNode)
			if !ok {
				if policy == imagePathCacheRelevance {
					return "", false, nil
				}
				return "", false, fmt.Errorf("image-local target is missing")
			}
			if !node.IsLink() {
				continue
			}
			if policy == imagePathResolution && node.LinkPath == "" {
				return "", false, fmt.Errorf("image-local link is malformed")
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
			return p, false, nil
		}
	}
	if policy == imagePathCacheRelevance {
		return "", false, nil
	}
	return "", false, fmt.Errorf("image-local link resolution limit exceeded")
}
