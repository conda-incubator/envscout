package discovery

import (
	"os"
	"syscall"
	"time"
)

// getFileCreateTS extracts the file creation timestamp from the stat info.
func getFileCreatedTS(info os.FileInfo) (time.Time, error) {
	raw := info.Sys().(*syscall.Stat_t).Birthtimespec
	return time.Unix(raw.Sec, raw.Nsec), nil
}
