//go:build darwin

package discovery

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// Snapshot mount points once instead of issuing an lstat for every directory.
// If the snapshot fails, the walker falls back to the ordinary device check.
type rootDevice struct {
	id       uint64
	mounts   map[string]bool
	snapshot bool
}

func newRootDevice(root string, info fs.FileInfo) (rootDevice, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return rootDevice{}, false
	}
	d := rootDevice{id: uint64(stat.Dev), mounts: map[string]bool{}}
	count, err := unix.Getfsstat(nil, unix.MNT_NOWAIT)
	if err != nil {
		return d, true
	}
	entries := make([]unix.Statfs_t, count+1)
	count, err = unix.Getfsstat(entries, unix.MNT_NOWAIT)
	if err != nil || count > len(entries) {
		return d, true
	}
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return d, true
	}
	for _, entry := range entries[:count] {
		mount := unix.ByteSliceToString(entry.Mntonname[:])
		rel, err := filepath.Rel(realRoot, mount)
		if err != nil || rel == "." || !isWithin(realRoot, mount) {
			continue
		}
		d.mounts[filepath.Join(root, rel)] = true
	}
	d.snapshot = true
	return d, true
}

// isWithin reports whether child is lexically inside (or equal to) parent.
func isWithin(parent, child string) bool {
	rel, err := filepath.Rel(parent, child)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

func (d rootDevice) needsInfo(p string) bool { return !d.snapshot || d.mounts[p] }

func (d rootDevice) same(p string, info fs.FileInfo) bool {
	if !d.needsInfo(p) {
		return true
	}
	if info == nil {
		var err error
		info, err = os.Lstat(p)
		if err != nil {
			return false
		}
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && uint64(stat.Dev) == d.id
}
