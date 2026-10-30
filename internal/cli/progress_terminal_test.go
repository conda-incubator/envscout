package cli

import (
	"bytes"
	"context"
	"io"
	"os"
	"testing"
)

func TestTerminalProgressEntryPointsKeepRedirectedOutputQuiet(t *testing.T) {
	for _, start := range []struct {
		name string
		call func(context.Context, io.Writer, bool) (context.Context, func() error)
	}{
		{"find", startDiscoveryProgress},
		{"scan", startScanProgress},
		{"lint", startLintProgress},
	} {
		t.Run(start.name, func(t *testing.T) {
			file, err := os.CreateTemp(t.TempDir(), "redirected")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = file.Close() }()
			var buffer bytes.Buffer
			canceled, cancel := context.WithCancel(context.Background())
			cancel()
			for _, test := range []struct {
				name    string
				ctx     context.Context
				writer  io.Writer
				enabled bool
			}{
				{"buffer", context.Background(), &buffer, true},
				{"file", context.Background(), file, true},
				{"disabled", context.Background(), file, false},
				{"canceled", canceled, file, true},
			} {
				t.Run(test.name, func(t *testing.T) {
					got, closeFn := start.call(test.ctx, test.writer, test.enabled)
					if got != test.ctx {
						t.Fatal("inactive progress must not attach counters")
					}
					for range 2 {
						if err := closeFn(); err != nil {
							t.Fatal(err)
						}
					}
				})
			}
			info, err := file.Stat()
			if err != nil || info.Size() != 0 || buffer.Len() != 0 {
				t.Fatalf("redirected progress must emit no bytes: info=%v buffer=%q err=%v", info, buffer.String(), err)
			}
		})
	}
}
