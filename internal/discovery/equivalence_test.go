package discovery

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/anaconda/envscout/internal/testimage"
)

// Host and image readers share one record and history contract: the same prefix shape
// must yield the same environment and revision from either source.
func TestHostAndImageEquivalence(t *testing.T) {
	host := t.TempDir()
	prefix := filepath.Join(host, "env")
	writeFile(t, filepath.Join(prefix, "conda-meta", "python.json"), imagePackageJSON)
	writeFile(t, filepath.Join(prefix, "conda-meta", "history"), "==> a <==\n==> b <==\n")

	hostReport, err := Find(context.Background(), []string{host}, true)
	if err != nil {
		t.Fatal(err)
	}
	img := loadDiscoveryImage(t, []testimage.Entry{
		{Name: "env/conda-meta/python.json", Data: imagePackageJSON},
		{Name: "env/conda-meta/history", Data: "==> a <==\n==> b <==\n"},
	})
	imageReport, err := FindImage(context.Background(), img, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(hostReport.Environments) != 1 || len(imageReport.Environments) != 1 {
		t.Fatalf("host=%+v image=%+v", hostReport.Environments, imageReport.Environments)
	}
	h, i := hostReport.Environments[0], imageReport.Environments[0]
	if h.Name != i.Name || h.Revision == nil || i.Revision == nil || *h.Revision != *i.Revision {
		t.Fatalf("host %+v != image %+v", h, i)
	}
}

// An explicit root named like a pruned directory is honored.
func TestExplicitRootOverridesSkipNames(t *testing.T) {
	root := t.TempDir()
	node := filepath.Join(root, "node_modules")
	makePrefix(t, filepath.Join(node, "env"))
	report, err := Find(context.Background(), []string{node}, false)
	if err != nil || len(report.Environments) != 1 {
		t.Fatalf("explicit pruned-name root not honored: %+v, %v", report, err)
	}
}

// The device seam accepts the root's own device. A different device is exercised by
// constructing rootDevice with a foreign identity; this is platform-specific and is
// skipped where the platform does not expose device identity.
func TestRootDeviceSeam(t *testing.T) {
	root := t.TempDir()
	info, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	dev, ok := newRootDevice(root, info)
	if !ok {
		t.Skip("device identity unavailable on this platform")
	}
	if !dev.same(root, info) {
		t.Fatal("root must match its own device")
	}
	if !dev.same(filepath.Join(root, "child"), info) {
		t.Fatal("child on the same device must match")
	}
}
