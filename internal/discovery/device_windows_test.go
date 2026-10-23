//go:build windows

package discovery

import "testing"

// mismatchedDevice returns a volume that cannot equal dev.
func mismatchedDevice(_ *testing.T, _ rootDevice) rootDevice {
	return rootDevice{volume: `Z:`}
}
