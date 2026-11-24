package discovery

import (
	"os"
	"syscall"
	"time"
)

// getFileCreateTS extracts the file creation timestamp from the stat info.
func getFileCreatedTS(info os.FileInfo) (time.Time, error) {
	raw := info.Sys().(*syscall.Win32FileAttributeData)
	return time.Unix(0, raw.CreationTime.Nanoseconds()), nil
}
