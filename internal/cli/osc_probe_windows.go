package cli

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ReadConsoleInputExW's NOWAIT avoids a blocking console read even after readiness.
var readOSCConsoleInput = windows.NewLazySystemDLL("kernel32.dll").NewProc("ReadConsoleInputExW")

type oscConsoleRecord struct {
	kind uint16
	_    uint16
	data [16]byte
}

var _ [20]byte = [unsafe.Sizeof(oscConsoleRecord{})]byte{}

func probeOSC7501(ctx context.Context, input, out *os.File) (supported bool, reason string, err error) {
	if err := ctx.Err(); err != nil {
		return false, "canceled", err
	}
	if readOSCConsoleInput.Find() != nil {
		return false, "unavailable-input", nil
	}
	in := windows.Handle(input.Fd())
	var mode uint32
	var info windows.ConsoleScreenBufferInfo
	if windows.GetConsoleMode(in, &mode) != nil || windows.GetConsoleScreenBufferInfo(windows.Handle(out.Fd()), &info) != nil {
		return false, "unavailable-input", nil
	}
	var record oscConsoleRecord
	read := func(flags uintptr) (uint32, error) {
		var n uint32
		ok, _, err := readOSCConsoleInput.Call(uintptr(in), uintptr(unsafe.Pointer(&record)), 1, uintptr(unsafe.Pointer(&n)), flags)
		if ok == 0 {
			return 0, err
		}
		return n, nil
	}
	// NOREMOVE | NOWAIT: never consume input queued before feature detection.
	if n, err := read(3); err != nil || n != 0 {
		return false, "unavailable-input", nil
	}
	// Keep processed input (Ctrl+C), changing only line/echo and VT input handling.
	if windows.SetConsoleMode(in, mode&^(windows.ENABLE_ECHO_INPUT|windows.ENABLE_LINE_INPUT)|windows.ENABLE_VIRTUAL_TERMINAL_INPUT) != nil {
		return false, "unavailable-input", nil
	}
	defer func() {
		if restore := windows.SetConsoleMode(in, mode); restore != nil {
			err = errors.Join(err, fmt.Errorf("restore OSC probe terminal: %w", restore))
		}
	}()
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
		n, err := read(2) // NOWAIT, including when the input queue becomes empty.
		if err != nil {
			return false, "probe-error", nil
		}
		if n == 0 {
			timer := time.NewTimer(min(time.Until(deadline), 5*time.Millisecond))
			select {
			case <-ctx.Done():
				timer.Stop()
				return false, "canceled", ctx.Err()
			case <-timer.C:
			}
			continue
		}
		if record.kind == 1 && binary.LittleEndian.Uint32(record.data[:4]) != 0 {
			char := binary.LittleEndian.Uint16(record.data[10:12])
			if char > 0 && char < 128 {
				reply = append(reply, byte(char))
			}
		}
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
