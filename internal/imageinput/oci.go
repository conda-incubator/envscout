// Package imageinput owns offline image loading, validation, and cleanup.
package imageinput

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/stereoscope/pkg/image/oci"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

// Limits bound bytes written by staging and by stereoscope's uncompressed cache.
// They do not constitute a process memory or wall-clock quota.
type Limits struct {
	ArchiveBytes, LayoutBytes, ExpandedBytes int64
	Entries, Layers                          int
}

func DefaultLimits() Limits {
	return Limits{ArchiveBytes: 1 << 30, LayoutBytes: 1 << 30, ExpandedBytes: 2 << 30, Entries: 250000, Layers: 128}
}

const maxJSONBytes = 4 << 20
const maxDescriptors = 256
const maxIndexDepth = 8
const maxLayerPathDepth = 128
const maxLayerNodes = 500000
const maxLayerPathBytes = 64 << 20

type Identity struct {
	Source         string `json:"source"`
	Input          string `json:"input"`
	ManifestDigest string `json:"manifest_digest"`
	ConfigDigest   string `json:"config_digest"`
	OS             string `json:"os"`
	Architecture   string `json:"architecture"`
	Variant        string `json:"variant,omitempty"`
}

// Loaded owns the one image used for discovery and inventory.
type Loaded struct {
	Image    *image.Image
	Identity Identity
	Manifest *v1.Manifest
	Config   *v1.ConfigFile
	stage    string
}

func (l *Loaded) Close() error {
	if l == nil {
		return nil
	}
	var err error
	if l.Image != nil {
		err = l.Image.Cleanup()
		l.Image = nil
	}
	if l.stage != "" {
		err = errors.Join(err, os.RemoveAll(l.stage))
		l.stage = ""
	}
	return err
}

func Load(ctx context.Context, input, platform string) (*Loaded, error) {
	return LoadWithLimits(ctx, input, platform, DefaultLimits())
}

// LoadWithLimits stages a regular OCI tar in a private directory, checks blob
// digests and expanded layer streams, then asks stereoscope to index it once.
func LoadWithLimits(ctx context.Context, input, platform string, limits Limits) (loaded *Loaded, err error) {
	if limits.ArchiveBytes <= 0 || limits.LayoutBytes <= 0 || limits.ExpandedBytes <= 0 || limits.Entries <= 0 || limits.Layers <= 0 {
		return nil, fmt.Errorf("image limits must be positive")
	}
	parts := strings.Split(platform, "/")
	if len(parts) < 2 || len(parts) > 3 {
		return nil, fmt.Errorf("OCI images require --platform OS/ARCH[/VARIANT]")
	}
	p, err := image.NewPlatform(platform)
	if err != nil || p == nil || p.OS != parts[0] || p.Architecture == "" {
		return nil, fmt.Errorf("invalid image platform %q", platform)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	abs, err := filepath.Abs(input)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(abs)
	if err != nil {
		return nil, fmt.Errorf("open OCI archive: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() > limits.ArchiveBytes {
		return nil, fmt.Errorf("OCI archive must be a regular non-symlink file of at most %d bytes", limits.ArchiveBytes)
	}
	f, err := os.Open(abs)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) || !opened.Mode().IsRegular() || opened.Size() > limits.ArchiveBytes {
		return nil, fmt.Errorf("OCI archive changed while opening")
	}
	stage, err := os.MkdirTemp("", "envscout-oci-")
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, os.RemoveAll(stage))
		}
	}()
	if err = stageArchive(ctx, f, stage, limits); err != nil {
		return nil, err
	}
	manifest, config, digest, err := selectImage(ctx, stage, p, limits)
	if err != nil {
		return nil, err
	}
	if err = validateLayers(ctx, stage, manifest, config, limits); err != nil {
		return nil, err
	}
	// A single selected manifest prevents the provider from choosing a host
	// platform or recursively visiting unselected, unvalidated index graphs.
	index := v1.IndexManifest{SchemaVersion: 2, MediaType: types.OCIImageIndex, Manifests: []v1.Descriptor{{MediaType: types.OCIManifestSchema1, Digest: digest, Platform: &v1.Platform{OS: config.OS, Architecture: config.Architecture, Variant: config.Variant}}}}
	data, err := json.Marshal(index)
	if err != nil {
		return nil, err
	}
	if err = os.WriteFile(filepath.Join(stage, "index.json"), data, 0o600); err != nil {
		return nil, err
	}
	gen := file.NewTempDirGenerator("envscout-image")
	img, err := oci.NewDirectoryProviderWithPlatform(gen, stage, p).Provide(ctx)
	if err != nil {
		if img != nil {
			err = errors.Join(err, img.Cleanup())
		}
		return nil, errors.Join(err, gen.Cleanup())
	}
	if img == nil {
		return nil, errors.Join(fmt.Errorf("image provider returned no image"), gen.Cleanup())
	}
	return &Loaded{Image: img, Manifest: manifest, Config: config, stage: stage, Identity: Identity{
		Source: "oci-archive", Input: abs, ManifestDigest: digest.String(), ConfigDigest: manifest.Config.Digest.String(),
		OS: config.OS, Architecture: config.Architecture, Variant: config.Variant,
	}}, nil
}

type checkedReader struct {
	ctx context.Context
	r   io.Reader
}

func (r checkedReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(p)
}

func stageArchive(ctx context.Context, input io.Reader, stage string, limits Limits) error {
	tr := tar.NewReader(checkedReader{ctx, io.LimitReader(input, limits.ArchiveBytes+1)})
	seen := make(map[string]bool)
	var total int64
	for count := 0; ; count++ {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("read OCI tar: %w", err)
		}
		if count >= limits.Entries {
			return fmt.Errorf("OCI archive entry limit exceeded")
		}
		name := path.Clean(h.Name)
		if strings.ContainsAny(h.Name, "\\\x00") || path.IsAbs(h.Name) || name == ".." || strings.HasPrefix(name, "../") || len(name) > 4096 {
			return fmt.Errorf("unsafe OCI archive path %q", h.Name)
		}
		if h.Typeflag == tar.TypeDir {
			if name != "." && name != "blobs" && name != "blobs/sha256" {
				return fmt.Errorf("unsupported OCI directory %q", name)
			}
			continue
		}
		if h.Typeflag != tar.TypeReg {
			return fmt.Errorf("OCI archive may contain only regular layout files")
		}
		blob := strings.TrimPrefix(name, "blobs/sha256/")
		isBlob := blob != name && validHash(blob)
		if name != "index.json" && name != "oci-layout" && !isBlob {
			return fmt.Errorf("not an OCI layout archive: unsupported entry %q (Docker-save archives are not supported)", name)
		}
		if seen[name] {
			return fmt.Errorf("duplicate OCI archive entry %q", name)
		}
		seen[name] = true
		if h.Size < 0 || h.Size > limits.LayoutBytes-total || (!isBlob && h.Size > maxJSONBytes) {
			return fmt.Errorf("OCI layout byte limit exceeded")
		}
		total += h.Size
		output := filepath.Join(stage, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(output), 0o700); err != nil {
			return err
		}
		f, err := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		hash := sha256.New()
		_, copyErr := io.CopyN(io.MultiWriter(f, hash), tr, h.Size)
		if err := errors.Join(copyErr, f.Close()); err != nil {
			return err
		}
		if isBlob && hex.EncodeToString(hash.Sum(nil)) != blob {
			return fmt.Errorf("OCI blob digest mismatch: %s", name)
		}
	}
	if !seen["oci-layout"] || !seen["index.json"] {
		return fmt.Errorf("archive is missing OCI layout markers")
	}
	var marker struct {
		Version string `json:"imageLayoutVersion"`
	}
	if err := readJSON(stage, "oci-layout", &marker); err != nil {
		return err
	}
	if marker.Version != "1.0.0" {
		return fmt.Errorf("unsupported OCI layout version %q", marker.Version)
	}
	return nil
}

func validHash(hash string) bool {
	if len(hash) != 64 {
		return false
	}
	for _, c := range hash {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func blobPath(stage string, descriptor v1.Descriptor) (string, error) {
	if descriptor.Digest.Algorithm != "sha256" || !validHash(descriptor.Digest.Hex) || len(descriptor.URLs) != 0 {
		return "", fmt.Errorf("unsupported or external OCI blob")
	}
	filename := filepath.Join(stage, "blobs", "sha256", descriptor.Digest.Hex)
	info, err := os.Stat(filename)
	if err != nil {
		return "", fmt.Errorf("missing OCI blob %s: %w", descriptor.Digest, err)
	}
	if descriptor.Size < 0 || info.Size() != descriptor.Size {
		return "", fmt.Errorf("OCI blob size mismatch: %s", descriptor.Digest)
	}
	return filename, nil
}

func readJSON(stage, filename string, value any) error {
	f, err := os.Open(filepath.Join(stage, filepath.FromSlash(filename)))
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil || info.Size() > maxJSONBytes {
		return fmt.Errorf("OCI JSON exceeds %d bytes", maxJSONBytes)
	}
	return json.NewDecoder(io.LimitReader(f, maxJSONBytes)).Decode(value)
}

func selectImage(ctx context.Context, stage string, platform *image.Platform, limits Limits) (*v1.Manifest, *v1.ConfigFile, v1.Hash, error) {
	var index v1.IndexManifest
	if err := readJSON(stage, "index.json", &index); err != nil {
		return nil, nil, v1.Hash{}, err
	}
	var selected *v1.Manifest
	var config *v1.ConfigFile
	var digest v1.Hash
	seen := make(map[string]bool)
	count := 0
	var visit func(v1.Descriptor, int) error
	visit = func(d v1.Descriptor, depth int) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		count++
		if depth > maxIndexDepth || count > maxDescriptors {
			return fmt.Errorf("OCI index depth/descriptor limit exceeded")
		}
		if d.Annotations["vnd.docker.reference.type"] == "attestation-manifest" || d.Platform != nil && d.Platform.OS == "unknown" && d.Platform.Architecture == "unknown" {
			return nil
		}
		filename, err := blobPath(stage, d)
		if err != nil {
			return err
		}
		if d.MediaType == types.OCIImageIndex {
			var nested v1.IndexManifest
			if err := readJSON(stage, filepath.ToSlash(strings.TrimPrefix(filename, stage+string(filepath.Separator))), &nested); err != nil {
				return err
			}
			for _, child := range nested.Manifests {
				if err := visit(child, depth+1); err != nil {
					return err
				}
			}
			return nil
		}
		if d.MediaType != types.OCIManifestSchema1 {
			return fmt.Errorf("unsupported OCI manifest media type %q", d.MediaType)
		}
		if seen[d.Digest.String()] {
			return nil
		}
		seen[d.Digest.String()] = true
		var m v1.Manifest
		if err := readJSON(stage, "blobs/sha256/"+d.Digest.Hex, &m); err != nil {
			return err
		}
		if len(m.Layers) > limits.Layers || m.SchemaVersion != 2 || m.Config.MediaType != types.OCIConfigJSON {
			return fmt.Errorf("unsupported OCI manifest or layer limit exceeded")
		}
		if _, err := blobPath(stage, m.Config); err != nil {
			return err
		}
		var c v1.ConfigFile
		if err := readJSON(stage, "blobs/sha256/"+m.Config.Digest.Hex, &c); err != nil {
			return err
		}
		actual, err := normalizedPlatform(c.OS, c.Architecture, c.Variant)
		if err != nil {
			return err
		}
		if d.Platform != nil {
			declared, err := normalizedPlatform(d.Platform.OS, d.Platform.Architecture, d.Platform.Variant)
			if err != nil || declared != actual {
				return fmt.Errorf("OCI descriptor/config platform mismatch")
			}
		}
		if actual != platform.String() {
			return nil
		}
		if selected != nil {
			return fmt.Errorf("multiple OCI images match platform %s", platform)
		}
		selected, config, digest = &m, &c, d.Digest
		return nil
	}
	for _, d := range index.Manifests {
		if err := visit(d, 0); err != nil {
			return nil, nil, v1.Hash{}, err
		}
	}
	if selected == nil {
		return nil, nil, v1.Hash{}, fmt.Errorf("no OCI image matches platform %s", platform)
	}
	return selected, config, digest, nil
}

func normalizedPlatform(osName, arch, variant string) (string, error) {
	spec := osName + "/" + arch
	if variant != "" {
		spec += "/" + variant
	}
	p, err := image.NewPlatform(spec)
	if err != nil || p.OS != osName || p.Architecture == "" {
		return "", fmt.Errorf("invalid OCI platform %q", spec)
	}
	return p.String(), nil
}

func validateLayers(ctx context.Context, stage string, manifest *v1.Manifest, config *v1.ConfigFile, limits Limits) error {
	if config.RootFS.Type != "layers" || len(config.RootFS.DiffIDs) != len(manifest.Layers) {
		return fmt.Errorf("OCI rootfs/layer count mismatch")
	}
	var expanded int64
	entries := 0
	// Missing parents are synthesized by stereoscope; count them before indexing
	// so short TAR headers cannot allocate an unbounded deep file tree.
	indexedNodes := 0
	allNodes := make(map[string]bool)
	pathBytes := 0
	for i, descriptor := range manifest.Layers {
		layerNodes := make(map[string]bool)
		filename, err := blobPath(stage, descriptor)
		if err != nil {
			return err
		}
		f, err := os.Open(filename)
		if err != nil {
			return err
		}
		var reader io.Reader = checkedReader{ctx, f}
		var gz *gzip.Reader
		switch descriptor.MediaType {
		case types.OCILayer:
			gz, err = gzip.NewReader(reader)
			reader = gz
		case types.OCIUncompressedLayer:
		default:
			err = fmt.Errorf("unsupported OCI layer media type %q (only tar and gzip are supported)", descriptor.MediaType)
		}
		if err != nil {
			_ = f.Close()
			return err
		}
		budget := &io.LimitedReader{R: checkedReader{ctx, reader}, N: limits.ExpandedBytes - expanded + 1}
		hash := sha256.New()
		stream := io.TeeReader(budget, hash)
		tr := tar.NewReader(stream)
		for {
			h, nextErr := tr.Next()
			if errors.Is(nextErr, io.EOF) {
				break
			}
			if nextErr != nil {
				err = nextErr
				break
			}
			entries++
			name := path.Clean(h.Name)
			if entries > limits.Entries || len(h.Name) > 4096 || strings.ContainsAny(h.Name, "\\\x00") || path.IsAbs(h.Name) || name == ".." || strings.HasPrefix(name, "../") {
				err = fmt.Errorf("image layer entry/path limit exceeded or unsafe path")
				break
			}
			if strings.Count(name, "/") >= maxLayerPathDepth {
				err = fmt.Errorf("image layer path depth limit exceeded")
				break
			}
			// Count distinct parents once in this diff and in the accumulated
			// squash. Keeping deleted paths is a conservative upper bound.
			for ancestor := name; ancestor != "."; ancestor = path.Dir(ancestor) {
				layerNodes[ancestor] = true
				if !allNodes[ancestor] {
					allNodes[ancestor] = true
					pathBytes += len(ancestor)
				}
				if indexedNodes+len(layerNodes)+len(allNodes) > maxLayerNodes || pathBytes > maxLayerPathBytes {
					err = fmt.Errorf("image layer synthesized-node/path memory limit exceeded")
					break
				}
			}
			if err != nil {
				break
			}
			if h.Size < 0 || h.Size > limits.ExpandedBytes-expanded {
				err = fmt.Errorf("expanded layer byte limit exceeded")
				break
			}
		}
		if err == nil {
			_, err = io.Copy(io.Discard, stream) // Reach EOF to verify gzip and diff ID.
		}
		expanded += limits.ExpandedBytes - expanded + 1 - budget.N
		if gz != nil {
			err = errors.Join(err, gz.Close())
		}
		err = errors.Join(err, f.Close())
		if expanded > limits.ExpandedBytes {
			return fmt.Errorf("expanded layer byte limit exceeded")
		}
		if err != nil {
			return fmt.Errorf("validate layer %d: %w", i, err)
		}
		if config.RootFS.DiffIDs[i].Algorithm != "sha256" || hex.EncodeToString(hash.Sum(nil)) != config.RootFS.DiffIDs[i].Hex {
			return fmt.Errorf("OCI layer %d diff ID mismatch", i)
		}
		indexedNodes += len(layerNodes) + len(allNodes)
	}
	return nil
}
