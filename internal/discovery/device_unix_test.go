//go:build unix

package discovery

import "testing"

// mismatchedDevice returns an identity that cannot equal dev.
func mismatchedDevice(_ *testing.T, dev rootDevice) rootDevice {
	return rootDevice{id: dev.id + 1}
}
