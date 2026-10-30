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
	"strings"
	"sync"

	stereofile "github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/source"
	"github.com/bmatcuk/doublestar/v4"
)

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
	r.issue = errors.Join(r.issue, err)
	return io.NopCloser(bytes.NewReader(data)), err
}

type hostRecordSource struct{ resolver *hostFileResolver }

func (s hostRecordSource) ID() artifact.ID                                  { return artifact.ID(FileID(s.resolver.base)) }
func (s hostRecordSource) FileResolver(source.Scope) (file.Resolver, error) { return s.resolver, nil }
func (s hostRecordSource) Describe() source.Description {
	return source.Description{ID: string(s.ID()), Name: s.resolver.base}
}
func (hostRecordSource) Close() error { return nil }
