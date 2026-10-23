//go:build unix && !darwin

package discovery

import (
	"io/fs"
	"syscall"
)

// rootDevice identifies the filesystem holding a root directory.
type rootDevice struct{ id uint64 }

func (d rootDevice) needsInfo(_ string) bool { return true }

func newRootDevice(root string, info fs.FileInfo) (rootDevice, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return rootDevice{}, false
	}
	return rootDevice{id: uint64(stat.Dev)}, true
}

// same reports whether entry (a directory under the root) is on the root's device. Callers
// obtain entry with DirEntry.Info, which performs one lstat per directory; that cost is
// real and is measured by the benchmarks rather than assumed away.
func (d rootDevice) same(_ string, entry fs.FileInfo) bool {
	stat, ok := entry.Sys().(*syscall.Stat_t)
	return ok && uint64(stat.Dev) == d.id
}
