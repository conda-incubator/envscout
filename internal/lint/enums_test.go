package lint

import (
	"encoding/json"
	"testing"
)

func TestSeverityRankAndValid(t *testing.T) {
	cases := []struct {
		s     Severity
		rank  int
		valid bool
	}{
		{Info, 1, true},
		{Warning, 2, true},
		{Error, 3, true},
		{NoFailure, 0, false},
		{Severity(""), 0, false},
		{Severity("critical"), 0, false},
	}
	for _, tc := range cases {
		if got := tc.s.Rank(); got != tc.rank {
			t.Errorf("Severity(%q).Rank() = %d, want %d", tc.s, got, tc.rank)
		}
		if got := tc.s.Valid(); got != tc.valid {
			t.Errorf("Severity(%q).Valid() = %v, want %v", tc.s, got, tc.valid)
		}
	}
	if Error.Rank() <= Warning.Rank() || Warning.Rank() <= Info.Rank() {
		t.Fatal("severity ranks must be strictly ordered info < warning < error")
	}
}

func TestSeverityAndStatusSerializeAsStrings(t *testing.T) {
	for _, tc := range []struct {
		v    any
		want string
	}{
		{Warning, `"warning"`},
		{NoFailure, `"none"`},
		{FindingStatus, `"finding"`},
		{NotApplicable, `"not_applicable"`},
		{Suppressed, `"suppressed"`},
	} {
		data, err := json.Marshal(tc.v)
		if err != nil {
			t.Fatal(err)
		}
		if string(data) != tc.want {
			t.Errorf("marshal %v = %s, want %s", tc.v, data, tc.want)
		}
	}
	var s Status
	if err := json.Unmarshal([]byte(`"unavailable"`), &s); err != nil || s != Unavailable {
		t.Fatalf("unmarshal Status = %q, %v", s, err)
	}
}

func TestStatusConstantsUnchangedValues(t *testing.T) {
	want := map[Status]string{
		Pass: "pass", FindingStatus: "finding", Unknown: "unknown", NotApplicable: "not_applicable",
		Disabled: "disabled", Unavailable: "unavailable", Suppressed: "suppressed",
	}
	for status, value := range want {
		if string(status) != value {
			t.Errorf("status %q changed value", value)
		}
	}
}
