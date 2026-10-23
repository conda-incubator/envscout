//go:build windows

package discovery

import (
	"io/fs"
	"path/filepath"
	"strings"
)

// rootDevice identifies the volume holding a root directory. io/fs exposes no POSIX
// device number on Windows, so the volume name of the absolute root path is used.
type rootDevice struct{ volume string }

func (d rootDevice) needsInfo(_ string) bool { return false }

func newRootDevice(root string, _ fs.FileInfo) (rootDevice, bool) {
	volume := filepath.VolumeName(root)
	return rootDevice{volume: volume}, volume != ""
}

// same reports whether path lies on the root's volume, judged by its path prefix. No stat is
// needed, so the entry info argument is unused on Windows.
func (d rootDevice) same(path string, _ fs.FileInfo) bool {
	return strings.EqualFold(filepath.VolumeName(path), d.volume)
}
