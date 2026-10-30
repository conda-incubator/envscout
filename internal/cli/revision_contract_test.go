package cli

import (
	"bytes"
	"testing"
)

func TestRevisionFormattersKeepPlainValues(t *testing.T) {
	for _, test := range []struct {
		value int
		want  string
	}{
		{-1, "-1"}, {0, "0"}, {2, "2"}, {3, "3"}, {5, "5"}, {6, "6"}, {123456, "123456"},
	} {
		t.Run(test.want, func(t *testing.T) {
			value := test.value
			if got := formatRevision(&value); got != test.want {
				t.Fatalf("plain revision = %q, want %q", got, test.want)
			}
			for _, noColor := range []bool{false, true} {
				if got := revisionCell(&value, &bytes.Buffer{}, noColor); got != test.want {
					t.Fatalf("redirected revision = %q, want %q", got, test.want)
				}
			}
		})
	}
	if got := formatRevision(nil); got != "?" {
		t.Fatalf("unknown plain revision = %q, want ?", got)
	}
}
