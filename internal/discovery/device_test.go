package discovery

import (
	"os"
	"path/filepath"
	"testing"
)

// The device seam compares the root's identity with an entry's identity. The "other
// device" case uses a mismatched identity of the same platform type, so no mount is
// needed and no Windows fake is involved.
func TestRootDeviceSameAndMismatch(t *testing.T) {
	root := t.TempDir()
	info, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	dev, ok := newRootDevice(root, info)
	if !ok {
		t.Skip("device identity unavailable on this platform")
	}
	child := filepath.Join(root, "child")
	if err := os.Mkdir(child, 0o755); err != nil {
		t.Fatal(err)
	}
	childInfo, err := os.Stat(child)
	if err != nil {
		t.Fatal(err)
	}
	if !dev.same(child, childInfo) {
		t.Fatal("same-device child reported as a mismatch")
	}
	mismatch := mismatchedDevice(t, dev)
	if mismatch.same(child, childInfo) {
		t.Fatal("different-device identity reported as the same device")
	}
}
