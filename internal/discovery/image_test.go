package discovery

import (
	"archive/tar"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/anaconda/envscout/internal/imageinput"
	"github.com/anaconda/envscout/internal/testimage"
	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/filetree"
	"github.com/anchore/stereoscope/pkg/filetree/filenode"
	"github.com/anchore/stereoscope/pkg/image"
)

const imagePackageJSON = `{"name":"python","version":"3.12"}`

func TestFindImageCondaFinalSquash(t *testing.T) {
	img := loadDiscoveryImage(t,
		[]testimage.Entry{
			{Name: "opt/base/conda-meta/python.json", Data: imagePackageJSON},
			{Name: "opt/base/conda-meta/history", Data: "==> old <==\n==> newer <==\n"},
			{Name: "opt/base/envs/nested/conda-meta/python.json", Data: imagePackageJSON},
			{Name: "gone/conda-meta/python.json", Data: imagePackageJSON},
			{Name: "opaque/conda-meta/python.json", Data: imagePackageJSON},
			{Name: "broken/conda-meta/bad.json", Data: `{"name":"python"}`},
			{Name: "empty/conda-meta", Type: tar.TypeDir},
			{Name: "loose/info/index.json", Data: imagePackageJSON},
		},
		[]testimage.Entry{
			{Name: "opt/base/conda-meta/history", Data: "==> current <==\n"},
			{Name: "gone/.wh.conda-meta"},
			{Name: "opaque/conda-meta/.wh..wh..opq"},
		},
	)
	report, err := FindImageConda(context.Background(), img)
	if err != nil {
		t.Fatal(err)
	}
	want := []Environment{
		{Name: "base", Path: "/opt/base", Revision: intPtr(0)},
		{Name: "nested", Path: "/opt/base/envs/nested", Revision: nil},
	}
	if !reflect.DeepEqual(report.Environments, want) {
		t.Fatalf("environments = %+v, want %+v", report.Environments, want)
	}
	if len(report.Issues) != 1 || report.Issues[0].Path != "/broken/conda-meta/bad.json" {
		t.Fatalf("issues = %+v", report.Issues)
	}
	if report.FilesVisited != len(img.SquashedTree().AllRealPaths()) {
		t.Fatalf("visited = %d, tree paths = %d", report.FilesVisited, len(img.SquashedTree().AllRealPaths()))
	}
}

func TestFindImageCondaNoHostHints(t *testing.T) {
	host := t.TempDir()
	makeCondaFixture(t, filepath.Join(host, "env"))
	t.Setenv("CONDA_PREFIX", filepath.Join(host, "env"))
	t.Setenv("CONDA_ENVS_PATH", host)
	img := loadDiscoveryImage(t, []testimage.Entry{{Name: "usr/bin/python", Data: "not an environment"}})
	report, err := FindImageConda(context.Background(), img)
	if err != nil || len(report.Environments) != 0 || len(report.Issues) != 0 {
		t.Fatalf("report = %+v, error = %v", report, err)
	}
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	if len(fields) != 6 || report.SchemaVersion != 1 || report.Source != "oci-archive" || report.Scope != "squashed" || string(fields["environments"]) != "[]" || string(fields["issues"]) != "[]" {
		t.Fatalf("unexpected image report JSON: %s", data)
	}
}

func TestFindImageCondaLinks(t *testing.T) {
	img := loadDiscoveryImage(t, []testimage.Entry{
		{Name: "usr/bin/python", Data: "python"},
		{Name: "bin", Type: tar.TypeSymlink, Link: "usr/bin"},
		{Name: "unrelated", Type: tar.TypeSymlink, Link: "missing"},
		{Name: "payload", Data: imagePackageJSON},
		{Name: "real/conda-meta/python.json", Data: imagePackageJSON},
		{Name: "alias", Type: tar.TypeSymlink, Link: "real"},
		{Name: "linked/conda-meta", Type: tar.TypeSymlink, Link: "/real/conda-meta"},
		{Name: "package-link/conda-meta/python.json", Type: tar.TypeSymlink, Link: "/payload"},
		{Name: "history-link/conda-meta/python.json", Data: imagePackageJSON},
		{Name: "history-link/conda-meta/history", Type: tar.TypeSymlink, Link: "/history-data"},
		{Name: "history-data", Data: "==> creation <==\n"},
		{Name: "cycle1", Type: tar.TypeSymlink, Link: "cycle2"},
		{Name: "cycle2", Type: tar.TypeSymlink, Link: "cycle1"},
	})
	report, err := FindImageConda(context.Background(), img)
	if err != nil {
		t.Fatal(err)
	}
	want := []Environment{{Name: "history-link", Path: "/history-link"}, {Name: "real", Path: "/real"}}
	if !reflect.DeepEqual(report.Environments, want) {
		t.Fatalf("environments = %+v, want %+v", report.Environments, want)
	}
	wantPaths := []string{"/alias", "/cycle1", "/cycle2", "/history-link/conda-meta/history", "/linked/conda-meta", "/package-link/conda-meta/python.json"}
	var paths []string
	for _, issue := range report.Issues {
		paths = append(paths, issue.Path)
	}
	if !reflect.DeepEqual(paths, wantPaths) {
		t.Fatalf("issues = %+v, want paths %+v", report.Issues, wantPaths)
	}
}

func TestFindImageCondaMalformedLinkTargets(t *testing.T) {
	tree := filetree.New()
	for _, link := range []struct{ name, target string }{{"/empty", ""}, {"/nul", "a\x00b"}} {
		if _, err := tree.AddSymLink(file.Path(link.name), file.Path(link.target)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := tree.AddHardLink("/directory-hardlink", "/"); err != nil {
		t.Fatal(err)
	}
	if _, err := tree.AddHardLink("/missing-hardlink", "/absent"); err != nil {
		t.Fatal(err)
	}
	img := &image.Image{Layers: []*image.Layer{{SquashedTree: tree}}, FileCatalog: image.NewFileCatalog()}
	report, err := FindImageConda(context.Background(), img)
	if err != nil || len(report.Environments) != 0 || len(report.Issues) != 4 {
		t.Fatalf("report = %+v, error = %v", report, err)
	}
	for _, issue := range report.Issues {
		if !strings.Contains(issue.Error, "malformed image") {
			t.Fatalf("unexpected issue: %+v", issue)
		}
	}
}

func TestFindImageCondaMetadataAndHistoryLimits(t *testing.T) {
	img := loadDiscoveryImage(t, []testimage.Entry{
		{Name: "env/conda-meta/aaa-valid.json", Data: imagePackageJSON},
		{Name: "env/conda-meta/invalid.json", Data: `not JSON`},
		{Name: "env/conda-meta/oversized.json", Data: strings.Repeat(" ", maxMetadataBytes+1)},
		{Name: "env/conda-meta/history", Data: strings.Repeat(" ", maxHistoryBytes+1)},
		{Name: "boundary/conda-meta/python.json", Data: imagePackageJSON + strings.Repeat(" ", maxMetadataBytes-len(imagePackageJSON))},
		{Name: "boundary/conda-meta/history", Data: "==> creation <==\n" + strings.Repeat("# line\n", 20)},
		{Name: "long-line/conda-meta/python.json", Data: imagePackageJSON},
		{Name: "long-line/conda-meta/history", Data: strings.Repeat("x", maxMetadataBytes+1)},
	})
	report, err := FindImageConda(context.Background(), img)
	if err != nil {
		t.Fatal(err)
	}
	want := []Environment{{Name: "boundary", Path: "/boundary", Revision: intPtr(0)}, {Name: "env", Path: "/env"}, {Name: "long-line", Path: "/long-line"}}
	if !reflect.DeepEqual(report.Environments, want) || len(report.Issues) != 4 {
		t.Fatalf("report = %+v, want environments %+v and four issues", report, want)
	}
	for _, issue := range report.Issues {
		if !strings.HasPrefix(issue.Path, "/env/conda-meta/") && issue.Path != "/long-line/conda-meta/history" {
			t.Fatalf("unexpected issue: %+v", issue)
		}
	}
}

func TestFindImageCondaMetadataEntryLimit(t *testing.T) {
	entries := []testimage.Entry{{Name: "env/conda-meta/000-valid.json", Data: imagePackageJSON}}
	for i := 0; i < maxMetadataEntries; i++ {
		entries = append(entries, testimage.Entry{Name: fmt.Sprintf("env/conda-meta/entry-%05d", i)})
	}
	img := loadDiscoveryImage(t, entries)
	report, err := FindImageConda(context.Background(), img)
	if err != nil || len(report.Environments) != 1 || len(report.Issues) != 1 || !strings.Contains(report.Issues[0].Error, "exceeds 10000 entries") {
		t.Fatalf("report = %+v, error = %v", report, err)
	}
}

func TestFindImageCondaNestedMetadataPrefix(t *testing.T) {
	img := loadDiscoveryImage(t, []testimage.Entry{
		{Name: "parent/conda-meta/python.json", Data: imagePackageJSON},
		{Name: "parent/conda-meta/nested/conda-meta/python.json", Data: imagePackageJSON},
	})
	report, err := FindImageConda(context.Background(), img)
	if err != nil || len(report.Environments) != 2 || len(report.Issues) != 0 {
		t.Fatalf("report = %+v, error = %v", report, err)
	}
}

func TestFindImageCondaPOSIXPaths(t *testing.T) {
	tree := filetree.New()
	ref, err := tree.AddFile(`/odd\name/conda-meta/python.json`)
	if err != nil {
		t.Fatal(err)
	}
	catalog := image.NewFileCatalog()
	catalog.Add(*ref, file.Metadata{FileInfo: file.ManualInfo{SizeValue: int64(len(imagePackageJSON))}, Type: file.TypeRegular}, nil, func() (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader(imagePackageJSON)), nil
	})
	img := &image.Image{Layers: []*image.Layer{{SquashedTree: tree}}, FileCatalog: catalog}
	report, err := FindImageConda(context.Background(), img)
	want := []Environment{{Name: `odd\name`, Path: `/odd\name`}}
	if err != nil || !reflect.DeepEqual(report.Environments, want) || len(report.Issues) != 0 {
		t.Fatalf("report = %+v, error = %v, want %+v", report, err, want)
	}
}

func TestReadImageCondaFileRejectsLinkAncestors(t *testing.T) {
	img := loadDiscoveryImage(t, []testimage.Entry{
		{Name: "env/conda-meta/python.json", Data: imagePackageJSON},
		{Name: "alias", Type: tar.TypeSymlink, Link: "env"},
	})
	_, err := readImageCondaFile(context.Background(), img, img.SquashedTree(), "/alias/conda-meta/python.json", maxMetadataBytes)
	if err == nil || !strings.Contains(err.Error(), "link at /alias") {
		t.Fatalf("error = %v, want ancestor link rejection", err)
	}
}

func TestFindImageCondaPathLimit(t *testing.T) {
	tree := &imageLimitTree{Reader: filetree.New()}
	img := &image.Image{Layers: []*image.Layer{{SquashedTree: tree}}, FileCatalog: image.NewFileCatalog()}
	report, err := FindImageConda(context.Background(), img)
	if err != nil || report.FilesVisited != maxImagePaths || len(report.Issues) != 1 || !strings.Contains(report.Issues[0].Error, "500000 visited paths") {
		t.Fatalf("report = %+v, error = %v", report, err)
	}
}

func TestFindImageCondaCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := FindImageConda(ctx, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want cancellation", err)
	}
	ctx, cancel = context.WithCancel(context.Background())
	closed := false
	img := discoveryContentImage(t, int64(len(imagePackageJSON)), func() (io.ReadCloser, error) {
		return &imageCancelReader{cancel: cancel, closed: &closed}, nil
	})
	if _, err := FindImageConda(ctx, img); !errors.Is(err, context.Canceled) || !closed {
		t.Fatalf("error = %v, reader closed = %t", err, closed)
	}
}

func TestFindImageCondaContentExceedsAdvertisedSize(t *testing.T) {
	img := discoveryContentImage(t, 1, func() (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader(imagePackageJSON + strings.Repeat(" ", maxMetadataBytes))), nil
	})
	report, err := FindImageConda(context.Background(), img)
	if err != nil || len(report.Environments) != 0 || len(report.Issues) != 1 || !strings.Contains(report.Issues[0].Error, "exceeds 1048576 bytes") {
		t.Fatalf("report = %+v, error = %v", report, err)
	}
}

func TestFindImageCondaInvalidImage(t *testing.T) {
	for _, img := range []*image.Image{nil, {}, {Layers: []*image.Layer{nil}}, {Layers: []*image.Layer{{}}}} {
		if _, err := FindImageConda(context.Background(), img); err == nil {
			t.Fatalf("expected unread image %+v to fail", img)
		}
	}
}

func loadDiscoveryImage(t *testing.T, layers ...[]testimage.Entry) *image.Image {
	t.Helper()
	loaded, err := imageinput.Load(context.Background(), testimage.Archive(t, layers...), "linux/amd64")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := loaded.Close(); err != nil {
			t.Error(err)
		}
	})
	return loaded.Image
}

func discoveryContentImage(t *testing.T, size int64, opener file.Opener) *image.Image {
	t.Helper()
	tree := filetree.New()
	ref, err := tree.AddFile("/env/conda-meta/python.json")
	if err != nil {
		t.Fatal(err)
	}
	catalog := image.NewFileCatalog()
	catalog.Add(*ref, file.Metadata{FileInfo: file.ManualInfo{SizeValue: size}, Type: file.TypeRegular}, nil, opener)
	return &image.Image{Layers: []*image.Layer{{SquashedTree: tree}}, FileCatalog: catalog}
}

type imageLimitTree struct{ filetree.Reader }

func (t *imageLimitTree) Walk(fn func(file.Path, filenode.FileNode) error, conditions *filetree.WalkConditions) error {
	for i := 0; i <= maxImagePaths; i++ {
		p := file.Path(fmt.Sprintf("/file-%d", i))
		node := *filenode.NewFile(p, nil)
		if conditions.ShouldTerminate(p, node) {
			return nil
		}
		if err := fn(p, node); err != nil {
			return err
		}
	}
	return nil
}

type imageCancelReader struct {
	cancel context.CancelFunc
	closed *bool
}

func (r *imageCancelReader) Read(p []byte) (int, error) {
	r.cancel()
	return copy(p, "{"), nil
}

func (r *imageCancelReader) Close() error {
	*r.closed = true
	return nil
}
