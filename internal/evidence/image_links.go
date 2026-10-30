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
