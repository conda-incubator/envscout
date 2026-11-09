//go:build darwin || linux

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

func probeOSC7501(ctx context.Context, input, out *os.File) (supported bool, reason string, err error) {
	if input == nil || out == nil {
		return false, "unavailable-input", nil
	}
	inInfo, inErr := input.Stat()
	outInfo, outErr := out.Stat()
	if inErr != nil || outErr != nil || !os.SameFile(inInfo, outInfo) {
		return false, "unavailable-input", nil
	}
	raw, err := input.SyscallConn()
	if err != nil {
		return false, "unavailable-input", nil
	}
	fd := -1
	if controlErr := raw.Control(func(handle uintptr) { fd, err = unix.FcntlInt(handle, unix.F_DUPFD_CLOEXEC, 0) }); controlErr != nil || err != nil {
		return false, "unavailable-input", nil
	}
	defer func() { _ = unix.Close(fd) }()
	if fd < 0 || fd > math.MaxInt32 {
		return false, "unavailable-input", nil
	}
	if err := ctx.Err(); err != nil {
		return false, "canceled", err
	}
	fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	// Switching canonical mode can disturb queued input on some terminals.
	// Check before changing any attributes, not only before writing the query.
	if ready, err := unix.Poll(fds, 0); err != nil || ready != 0 {
		return false, "unavailable-input", nil
	}
	original, err := unix.IoctlGetTermios(fd, oscTermiosGet)
	if err != nil {
		return false, "unavailable-input", nil
	}
	mode := *original
	// Preserve ISIG (Ctrl+C) and output processing; only replies need character input.
	mode.Lflag &^= unix.ECHO | unix.ICANON | unix.ECHONL
	mode.Cc[unix.VMIN], mode.Cc[unix.VTIME] = 0, 0
	if unix.IoctlSetTermios(fd, oscTermiosSet, &mode) != nil {
		return false, "unavailable-input", nil
	}
	defer func() {
		if restore := unix.IoctlSetTermios(fd, oscTermiosSet, original); restore != nil {
			err = errors.Join(err, fmt.Errorf("restore OSC probe terminal: %w", restore))
		}
	}()
	if ready, err := unix.Poll(fds, 0); err != nil || ready != 0 {
		return false, "unavailable-input", nil
	}
	if n, err := io.WriteString(out, oscQuery); err != nil || n != len(oscQuery) {
		if err == nil {
			err = io.ErrShortWrite
		}
		return false, "write-failed", err
	}
	deadline := time.Now().Add(oscProbeTimeout)
	var reply []byte
	for time.Now().Before(deadline) {
		if err := ctx.Err(); err != nil {
			return false, "canceled", err
		}
		fds[0].Revents = 0
		ready, err := unix.Poll(fds, max(1, int(min(time.Until(deadline), 10*time.Millisecond)/time.Millisecond)))
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return false, "probe-error", nil
		}
		if ready == 0 {
			continue
		}
		if fds[0].Revents&unix.POLLIN == 0 {
			return false, "unavailable-input", nil
		}
		// Do not read beyond the transaction's DA terminator into subsequent input.
		var char [1]byte
		n, err := unix.Read(fd, char[:])
		if errors.Is(err, unix.EINTR) || errors.Is(err, unix.EAGAIN) {
			continue
		}
		if err != nil {
			return false, "probe-error", nil
		}
		if n == 0 {
			return false, "unavailable-input", nil
		}
		reply = append(reply, char[0])
		if len(reply) > 4096 {
			return false, "invalid-reply", nil
		}
		var finished bool
		supported, finished = interpretOSCReply(reply)
		if finished {
			if supported {
				return true, "supported", nil
			}
			return false, "unsupported", nil
		}
	}
	if supported {
		return true, "supported", nil
	}
	return false, "timeout", nil
}
