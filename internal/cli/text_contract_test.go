package cli

import "testing"

func TestDisplayTextKeepsExistingEscaping(t *testing.T) {
	for _, test := range []struct {
		name, input, want string
	}{
		{"empty", "", ""},
		{"plain", `C:\env\100%s`, `C:\env\100%s`},
		{"unicode", "caf\u00e9", "caf\u00e9"},
		{"newline", "env\nname", `"env\nname"`},
		{"escape", "\x1b[31mred", `"\x1b[31mred"`},
		{"delete", "env\x7f", `"env\x7f"`},
		{"unicode control", "env\u0085", `"env\u0085"`},
		{"unicode and control", "caf\u00e9\n", `"caf\u00e9\n"`},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := safeText(test.input); got != test.want {
				t.Fatalf("display text = %q, want %q", got, test.want)
			}
		})
	}
}
