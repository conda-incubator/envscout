//go:build !darwin && !linux && !windows

package cli

import (
	"context"
	"os"
)

func probeOSC7501(context.Context, *os.File, *os.File) (bool, string, error) {
	return false, "unavailable-input", nil
}
