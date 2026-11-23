package discovery

import (
	"os"
	"syscall"
	"time"
)

// getFileCreateTS extracts the file creation timestamp from the stat info.
func getFileCreatedTS(info os.FileInfo) (time.Time, error) {
	// Stat_t.Ctim isn't necessarily correct but usually close enough.
	// XXX Try Statx() (from golang.org/x/sys/unix)?
	raw := info.Sys().(*syscall.Stat_t).Ctim
	return time.Unix(raw.Sec, raw.Nsec), nil
}
