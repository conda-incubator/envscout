//go:build darwin || linux

package cli

import "testing"

func TestRevisionCellKeepsTerminalColorsAndUnknown(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	_, terminal := progressPTY(t)
	if !isTerminal(terminal) {
		t.Fatal("fixture must be an operating-system terminal")
	}
	for _, test := range []struct {
		value          int
		plain, colored string
	}{
		{0, "0", "\x1b[32m0\x1b[0m"},
		{2, "2", "\x1b[33m2\x1b[0m"},
		{3, "3", "\x1b[93m3\x1b[0m"},
		{5, "5", "\x1b[93m5\x1b[0m"},
		{6, "6", "\x1b[31m6\x1b[0m"},
	} {
		t.Run(test.plain, func(t *testing.T) {
			value := test.value
			if got := revisionCell(&value, terminal, false); got != test.colored {
				t.Fatalf("colored revision = %q, want %q", got, test.colored)
			}
			if got := revisionCell(&value, terminal, true); got != test.plain {
				t.Fatalf("--no-color revision = %q, want %q", got, test.plain)
			}
		})
	}
	if got := revisionCell(nil, terminal, false); got != "?" {
		t.Fatalf("unknown revision must remain uncolored: %q", got)
	}
	t.Setenv("NO_COLOR", "1")
	value := 6
	if got := revisionCell(&value, terminal, false); got != "6" {
		t.Fatalf("NO_COLOR revision = %q, want 6", got)
	}
}
