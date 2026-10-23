//go:build darwin

package discovery

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMountPathContainment(t *testing.T) {
	for _, tt := range []struct {
		parent, child string
		want          bool
	}{
		{"/scan", "/scan", true},
		{"/scan", "/scan/mounted", true},
		{"/scan", "/", false},
		{"/scan", "/scan-other/mounted", false},
	} {
		if got := isWithin(tt.parent, tt.child); got != tt.want {
			t.Errorf("isWithin(%q, %q) = %t, want %t", tt.parent, tt.child, got, tt.want)
		}
	}
}

func TestMountSnapshotAvoidsOrdinaryDirectoryStats(t *testing.T) {
	root := t.TempDir()
	info, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	device, ok := newRootDevice(root, info)
	if !ok || !device.snapshot {
		t.Fatal("mount snapshot unavailable")
	}
	child := filepath.Join(root, "ordinary")
	if device.needsInfo(child) || !device.same(child, nil) {
		t.Fatal("ordinary directories should not need a device stat")
	}
	device.mounts[child] = true
	if !device.needsInfo(child) {
		t.Fatal("mount boundaries must still be checked")
	}
	device.snapshot = false
	if !device.needsInfo(filepath.Join(root, "fallback")) {
		t.Fatal("unavailable snapshot must fall back to device stats")
	}
}
