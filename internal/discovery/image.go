package discovery

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"sort"
	"strings"

	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/filetree"
	"github.com/anchore/stereoscope/pkg/filetree/filenode"
	"github.com/anchore/stereoscope/pkg/image"
)

const maxImagePaths = 500000

// ImageReport describes discovery in the final, runtime-visible image filesystem.
// The caller supplies image identity separately and retains ownership of the image.
type ImageReport struct {
	SchemaVersion int           `json:"schema_version"`
	Source        string        `json:"source"`
	Scope         string        `json:"scope"`
	Environments  []Environment `json:"environments"`
	Issues        []Issue       `json:"issues"`
	FilesVisited  int           `json:"files_visited"`
}

// FindImageConda searches only the final squash, using image POSIX paths and no host hints.
// Coverage limits and unreadable evidence are issues; cancellation is returned as an error.
func FindImageConda(ctx context.Context, img *image.Image) (ImageReport, error) {
	report := ImageReport{SchemaVersion: 1, Source: "oci-archive", Scope: "squashed", Environments: []Environment{}, Issues: []Issue{}}
	if err := ctx.Err(); err != nil {
		return report, err
	}
	if img == nil {
		return report, fmt.Errorf("image is required")
	}
	if len(img.Layers) > 0 && img.Layers[len(img.Layers)-1] == nil {
		return report, fmt.Errorf("image has no final layer")
	}
	tree := img.SquashedTree()
	if tree == nil || img.FileCatalog == nil {
		return report, fmt.Errorf("image must be read before discovery")
	}
	defer func() {
		sort.Slice(report.Environments, func(i, j int) bool { return report.Environments[i].Path < report.Environments[j].Path })
		sort.Slice(report.Issues, func(i, j int) bool {
			if report.Issues[i].Path == report.Issues[j].Path {
				return report.Issues[i].Error < report.Issues[j].Error
			}
			return report.Issues[i].Path < report.Issues[j].Path
		})
	}()

	type candidate struct {
		entries int
		valid   bool
		history bool
	}
	prefixes := make(map[string]*candidate)
	addIssue := func(p string, err error) {
		report.Issues = append(report.Issues, Issue{Path: p, Error: err.Error()})
	}
	err := tree.Walk(func(p file.Path, node filenode.FileNode) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		report.FilesVisited++
		name := string(p)
		parent := path.Dir(name)
		prefix := prefixes[parent]
		if prefix != nil {
			prefix.entries++
			if prefix.entries == maxMetadataEntries+1 {
				addIssue(parent, fmt.Errorf("conda-meta exceeds %d entries", maxMetadataEntries))
			}
		}
		if node.IsLink() {
			if err := imageCondaLink(ctx, tree, p, node); err != nil {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				addIssue(name, err)
			}
			return nil
		}
		if path.Base(name) == "conda-meta" {
			if node.FileType != file.TypeDirectory {
				addIssue(name, fmt.Errorf("conda-meta is not a directory"))
			} else {
				prefixes[name] = &candidate{}
			}
			return nil
		}
		if prefix == nil {
			return nil
		}
		if path.Base(name) == "history" {
			prefix.history = true
			return nil
		}
		if prefix.entries > maxMetadataEntries || node.FileType == file.TypeDirectory || path.Ext(name) != ".json" {
			return nil
		}
		data, err := readImageCondaFile(ctx, img, tree, name, maxMetadataBytes)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			addIssue(name, err)
		} else {
			valid := validPackageMetadata(imageContextReader{ctx: ctx, reader: bytes.NewReader(data)})
			if err := ctx.Err(); err != nil {
				return err
			}
			if valid {
				prefix.valid = true
			} else {
				addIssue(name, fmt.Errorf("invalid conda package metadata"))
			}
		}
		return nil
	}, &filetree.WalkConditions{
		// A nil slice enables stereoscope's default basename link following.
		LinkOptions: []filetree.LinkResolutionOption{},
		ShouldContinueBranch: func(_ file.Path, node filenode.FileNode) bool {
			return !node.IsLink()
		},
		ShouldTerminate: func(p file.Path, _ filenode.FileNode) bool {
			if ctx.Err() != nil {
				return true
			}
			if report.FilesVisited >= maxImagePaths {
				addIssue(string(p), fmt.Errorf("image discovery exceeds %d visited paths", maxImagePaths))
				return true
			}
			return false
		},
	})
	if ctx.Err() != nil {
		return report, ctx.Err()
	}
	if err != nil {
		addIssue("/", fmt.Errorf("walk image squash: %w", err))
	}
	for metaDir, prefix := range prefixes {
		if err := ctx.Err(); err != nil {
			return report, err
		}
		if !prefix.valid {
			continue
		}
		var rev *int
		if prefix.history {
			history := path.Join(metaDir, "history")
			data, readErr := readImageCondaFile(ctx, img, tree, history, maxHistoryBytes)
			if ctx.Err() != nil {
				return report, ctx.Err()
			}
			if readErr == nil {
				rev, readErr = revisionFromReader(imageContextReader{ctx: ctx, reader: bytes.NewReader(data)})
			}
			if ctx.Err() != nil {
				return report, ctx.Err()
			}
			if readErr != nil && !errors.Is(readErr, fs.ErrNotExist) {
				addIssue(history, readErr)
			}
		}
		envPath := path.Dir(metaDir)
		report.Environments = append(report.Environments, Environment{Name: path.Base(envPath), Path: envPath, Revision: rev})
	}
	return report, nil
}

// imageCondaLink checks links only for malformed resolution or conda evidence.
// Ordinary links elsewhere in the filesystem are deliberately not coverage gaps.
func imageCondaLink(ctx context.Context, tree filetree.Reader, p file.Path, node filenode.FileNode) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if node.LinkPath == "" || strings.ContainsRune(string(node.LinkPath), '\x00') {
		return fmt.Errorf("malformed image link")
	}
	found, resolved, err := tree.File(p, filetree.FollowBasenameLinks)
	if err != nil {
		return fmt.Errorf("malformed image link: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if node.FileType == file.TypeHardLink {
		if !found || !resolved.HasReference() {
			return fmt.Errorf("malformed image hardlink: target is missing or a directory")
		}
		raw := tree.TreeReader().Node(filenode.IDByPath(resolved.RealPath))
		if target, ok := raw.(*filenode.FileNode); !ok || target.FileType == file.TypeDirectory {
			return fmt.Errorf("malformed image hardlink: target is not a file")
		}
	}
	isEvidence := func(name string) bool {
		return path.Base(name) == "conda-meta" || path.Base(path.Dir(name)) == "conda-meta" && (path.Base(name) == "history" || path.Ext(name) == ".json")
	}
	if isEvidence(string(p)) {
		return fmt.Errorf("conda evidence is a link; links are not followed")
	}
	target := string(node.LinkPath)
	if !path.IsAbs(target) {
		target = path.Join(path.Dir(string(p)), target)
	}
	if found && resolved.HasReference() {
		target = string(resolved.RealPath)
	}
	if isEvidence(target) {
		return fmt.Errorf("link points to conda evidence; links are not followed")
	}
	// Looking for the marker is evidence-only: never open a resolved link target.
	found, _, err = tree.File(file.Path(path.Join(target, "conda-meta")))
	if err != nil {
		return fmt.Errorf("malformed conda evidence link: %w", err)
	}
	if found {
		return fmt.Errorf("link points to a conda prefix; links are not followed")
	}
	return ctx.Err()
}

func readImageCondaFile(ctx context.Context, img *image.Image, tree filetree.Reader, name string, limit int64) ([]byte, error) {
	// File can resolve ancestor links even without FollowBasenameLinks. Inspect
	// exact ancestor nodes first, including synthetic directories without references.
	parts := strings.Split(strings.TrimPrefix(name, "/"), "/")
	current := ""
	for i, part := range parts {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		current += "/" + part
		raw := tree.TreeReader().Node(filenode.IDByPath(file.Path(current)))
		if raw == nil {
			return nil, fs.ErrNotExist
		}
		node, ok := raw.(*filenode.FileNode)
		if !ok || node.IsLink() {
			return nil, fmt.Errorf("conda evidence has a link at %s", current)
		}
		if i < len(parts)-1 && node.FileType != file.TypeDirectory {
			return nil, fmt.Errorf("conda evidence ancestor is not a directory: %s", current)
		}
		if i == len(parts)-1 && node.FileType != file.TypeRegular {
			return nil, fmt.Errorf("conda evidence is not a regular file")
		}
	}
	found, resolved, err := tree.File(file.Path(name))
	if err != nil {
		return nil, err
	}
	if !found || !resolved.HasReference() {
		return nil, fs.ErrNotExist
	}
	entry, err := img.FileCatalog.Get(*resolved.Reference)
	if err != nil {
		return nil, err
	}
	if entry.FileInfo == nil || entry.Type != file.TypeRegular || !entry.Mode().IsRegular() || entry.Size() < 0 || entry.Size() > limit {
		return nil, fmt.Errorf("conda evidence is not a regular file of at most %d bytes", limit)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	reader, err := img.OpenReference(*resolved.Reference)
	if err != nil {
		return nil, err
	}
	data, readErr := io.ReadAll(io.LimitReader(imageContextReader{ctx: ctx, reader: reader}, limit+1))
	closeErr := reader.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("conda evidence exceeds %d bytes", limit)
	}
	return data, ctx.Err()
}

type imageContextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r imageContextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}
