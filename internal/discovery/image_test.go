package discovery

import (
	"archive/tar"
	"context"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/anaconda/envscout/internal/imageinput"
	"github.com/anaconda/envscout/internal/testimage"
	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/filetree"
	"github.com/anchore/stereoscope/pkg/image"
)

const imagePackageJSON = `{"name":"python","version":"3.12"}`

func TestFindImageFinalSquash(t *testing.T) {
	img := loadDiscoveryImage(t,
		[]testimage.Entry{
			{Name: "opt/base/conda-meta/python.json", Data: imagePackageJSON},
			{Name: "opt/base/conda-meta/history", Data: "==> old <==\n==> newer <==\n"},
			{Name: "opt/base/envs/nested/conda-meta/python.json", Data: imagePackageJSON},
			{Name: "gone/conda-meta/python.json", Data: imagePackageJSON},
			{Name: "opaque/conda-meta/python.json", Data: imagePackageJSON},
			{Name: "broken/conda-meta/bad.json", Data: `{"name":"python"}`},
			{Name: "loose/info/index.json", Data: imagePackageJSON},
		},
		[]testimage.Entry{
			{Name: "opt/base/conda-meta/history", Data: "==> current <==\n"},
			{Name: "gone/.wh.conda-meta"},
			{Name: "opaque/conda-meta/.wh..wh..opq"},
		},
	)
	report, err := FindImage(context.Background(), img, true)
	if err != nil {
		t.Fatal(err)
	}
	want := []Environment{
		{Name: "broken", Path: "/broken"},
		{Name: "base", Path: "/opt/base", Revision: intPtr(0)},
		{Name: "nested", Path: "/opt/base/envs/nested", Revision: nil},
	}
	if !reflect.DeepEqual(report.Environments, want) {
		t.Fatalf("environments = %+v, want %+v", report.Environments, want)
	}
	// Only conda-meta *.json matches are examined; the count is not the whole tree.
	if report.MetadataFilesExamined == 0 || report.MetadataFilesExamined >= len(img.SquashedTree().AllRealPaths()) {
		t.Fatalf("examined = %d, tree paths = %d", report.MetadataFilesExamined, len(img.SquashedTree().AllRealPaths()))
	}
}

func TestFindImageHistorySkipped(t *testing.T) {
	img := loadDiscoveryImage(t, []testimage.Entry{
		{Name: "env/conda-meta/python.json", Data: imagePackageJSON},
		{Name: "env/conda-meta/history", Data: "==> creation <==\n"},
	})
	report, err := FindImage(context.Background(), img, false)
	if err != nil || len(report.Environments) != 1 || report.Environments[0].Revision != nil {
		t.Fatalf("history read when not requested: %+v, %v", report, err)
	}
}

func TestFindImageNoHostHints(t *testing.T) {
	host := t.TempDir()
	makePrefix(t, filepath.Join(host, "env"))
	t.Setenv("CONDA_PREFIX", filepath.Join(host, "env"))
	t.Setenv("CONDA_ENVS_PATH", host)
	img := loadDiscoveryImage(t, []testimage.Entry{{Name: "usr/bin/python", Data: "not an environment"}})
	report, err := FindImage(context.Background(), img, true)
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
	if report.SchemaVersion != 1 || report.Source != "oci-archive" || report.Scope != "squashed" || string(fields["environments"]) != "[]" || string(fields["issues"]) != "[]" {
		t.Fatalf("unexpected image report JSON: %s", data)
	}
}

func TestFindImageLinks(t *testing.T) {
	img := loadDiscoveryImage(t, []testimage.Entry{
		{Name: "usr/bin/python", Data: "python"},
		{Name: "bin", Type: tar.TypeSymlink, Link: "usr/bin"},
		{Name: "payload", Data: imagePackageJSON},
		{Name: "real/conda-meta/python.json", Data: imagePackageJSON},
		{Name: "alias", Type: tar.TypeSymlink, Link: "real"},
		{Name: "linked/conda-meta", Type: tar.TypeSymlink, Link: "/real/conda-meta"},
		{Name: "package-link/conda-meta/python.json", Type: tar.TypeSymlink, Link: "/payload"},
	})
	report, err := FindImage(context.Background(), img, false)
	if err != nil {
		t.Fatal(err)
	}
	want := []Environment{{Name: "real", Path: "/real"}}
	if !reflect.DeepEqual(report.Environments, want) {
		t.Fatalf("environments = %+v, want %+v", report.Environments, want)
	}
	for _, issue := range report.Issues {
		if !strings.Contains(issue.Error, "link") && !strings.Contains(issue.Error, "absent") {
			t.Fatalf("unexpected issue: %+v", issue)
		}
	}
}

func TestFindImageMalformedLinkTargets(t *testing.T) {
	tree := filetree.New()
	for _, link := range []struct{ name, target string }{{"/empty", ""}, {"/nul", "a\x00b"}} {
		if _, err := tree.AddSymLink(file.Path(link.name), file.Path(link.target)); err != nil {
			t.Fatal(err)
		}
	}
	img := &image.Image{Layers: []*image.Layer{{SquashedTree: tree}}, FileCatalog: image.NewFileCatalog()}
	report, err := FindImage(context.Background(), img, false)
	if err != nil || len(report.Environments) != 0 {
		t.Fatalf("report = %+v, error = %v", report, err)
	}
}

// Invalid JSON with a regular .json name is still a candidate; validation is deferred.
func TestFindImageCandidateIsFilenameOnly(t *testing.T) {
	img := loadDiscoveryImage(t, []testimage.Entry{
		{Name: "env/conda-meta/invalid.json", Data: `not JSON`},
	})
	report, err := FindImage(context.Background(), img, false)
	if err != nil || len(report.Environments) != 1 || len(report.Issues) != 0 {
		t.Fatalf("report = %+v, error = %v", report, err)
	}
}

func TestFindImageNestedMetadataPrefix(t *testing.T) {
	img := loadDiscoveryImage(t, []testimage.Entry{
		{Name: "parent/conda-meta/python.json", Data: imagePackageJSON},
		{Name: "parent/conda-meta/nested/conda-meta/python.json", Data: imagePackageJSON},
	})
	report, err := FindImage(context.Background(), img, false)
	if err != nil || len(report.Environments) != 2 || len(report.Issues) != 0 {
		t.Fatalf("report = %+v, error = %v", report, err)
	}
}

func TestFindImagePOSIXPaths(t *testing.T) {
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
	report, err := FindImage(context.Background(), img, false)
	want := []Environment{{Name: `odd\name`, Path: `/odd\name`}}
	if err != nil || !reflect.DeepEqual(report.Environments, want) || len(report.Issues) != 0 {
		t.Fatalf("report = %+v, error = %v, want %+v", report, err, want)
	}
}

func TestFindImageCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := FindImage(ctx, nil, false); !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want cancellation", err)
	}
	// Only history is read as content, so cancellation is observed during that read.
	ctx, cancel = context.WithCancel(context.Background())
	closed := false
	img := discoveryHistoryImage(t, func() (io.ReadCloser, error) {
		return &imageCancelReader{cancel: cancel, closed: &closed}, nil
	})
	if _, err := FindImage(ctx, img, true); !errors.Is(err, context.Canceled) || !closed {
		t.Fatalf("error = %v, reader closed = %t", err, closed)
	}
}

func discoveryHistoryImage(t *testing.T, opener file.Opener) *image.Image {
	t.Helper()
	tree := filetree.New()
	record, err := tree.AddFile("/env/conda-meta/python.json")
	if err != nil {
		t.Fatal(err)
	}
	ref, err := tree.AddFile("/env/conda-meta/history")
	if err != nil {
		t.Fatal(err)
	}
	catalog := image.NewFileCatalog()
	catalog.Add(*record, file.Metadata{FileInfo: file.ManualInfo{SizeValue: int64(len(imagePackageJSON))}, Type: file.TypeRegular}, nil, func() (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader(imagePackageJSON)), nil
	})
	catalog.Add(*ref, file.Metadata{FileInfo: file.ManualInfo{SizeValue: 16}, Type: file.TypeRegular}, nil, opener)
	return &image.Image{Layers: []*image.Layer{{SquashedTree: tree}}, FileCatalog: catalog}
}

func TestFindImageInvalidImage(t *testing.T) {
	for _, img := range []*image.Image{nil, {}, {Layers: []*image.Layer{nil}}, {Layers: []*image.Layer{{}}}} {
		if _, err := FindImage(context.Background(), img, false); err == nil {
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
