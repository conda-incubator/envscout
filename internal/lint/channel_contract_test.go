package lint

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/conda-incubator/envscout/internal/inventory"
)

// channelRecord reuses the shared localRecord fixture and only overrides the
// channel fields under test.
func channelRecord(name, version, channel, subdir string) inventory.CondaRecord {
	r := localRecord(name, version)
	r.Record.Channel, r.Record.Subdir = channel, subdir
	return r
}

// Oracles below are measured from go-rattler v0.0.4 CanonicalChannel output.
func TestLocalChannelMeasuredOracles(t *testing.T) {
	for _, test := range []struct {
		name, channel, subdir, canonical string
		valid                            bool
	}{
		{"defaults main with explicit subdir", "https://repo.anaconda.com/pkgs/main/linux-64", "linux-64", "https://repo.anaconda.com/pkgs/main/", true},
		{"defaults main without subdir", "https://repo.anaconda.com/pkgs/main", "linux-64", "https://repo.anaconda.com/pkgs/main/", true},
		{"r channel", "https://repo.anaconda.com/pkgs/r", "linux-64", "https://repo.anaconda.com/pkgs/r/", true},
		{"msys2 channel", "https://repo.anaconda.com/pkgs/msys2", "win-64", "https://repo.anaconda.com/pkgs/msys2/", true},
		{"forge bare", "https://conda.anaconda.org/conda-forge", "linux-64", "https://conda.anaconda.org/conda-forge/", true},
		{"forge explicit subdir", "https://conda.anaconda.org/conda-forge/linux-64", "linux-64", "https://conda.anaconda.org/conda-forge/", true},
		{"custom channel", "https://example.test/private/channel", "linux-64", "https://example.test/private/channel/", true},
		// Canonicalization lowercases the host, so EqualFold in callers is redundant here.
		{"uppercase host", "https://REPO.ANACONDA.COM/pkgs/main", "linux-64", "https://repo.anaconda.com/pkgs/main/", true},
		{"subdir mismatch is not trimmed", "https://example.test/conda-forge/linux-64", "osx-64", "https://example.test/conda-forge/linux-64/", true},
		{"subdir-like suffix without explicit subdir is kept", "https://example.test/linux-64", "", "https://example.test/linux-64/", true},
		// Only one trailing slash is trimmed before re-adding one, so a doubled slash is preserved.
		{"repeated trailing slash", "https://conda.anaconda.org/conda-forge//", "", "https://conda.anaconda.org/conda-forge//", true},
		{"bare alias defaults is invalid", "defaults", "linux-64", "", false},
		{"bare alias conda-forge", "conda-forge", "linux-64", "https://conda.anaconda.org/conda-forge/", true},
		{"empty channel", "", "linux-64", "", false},
		{"userinfo credentials redacted", "https://secret:password@conda.anaconda.org/conda-forge/linux-64", "linux-64", "https://conda.anaconda.org/conda-forge/", true},
		// Known gap: userinfo is dropped, but query and fragment survive. This pins current output, not a redaction guarantee.
		{"query and fragment retained (known gap)", "https://secret:password@conda.anaconda.org/conda-forge/linux-64?token=TOKEN#frag", "linux-64", "https://conda.anaconda.org/conda-forge/?token=TOKEN#frag", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			record := channelRecord("certifi", "2026.7.22", test.channel, test.subdir)
			facts, valid := condaChannelFacts(record.Record)
			canonical := facts.identity
			if canonical != test.canonical || valid != test.valid {
				t.Fatalf("condaChannelFacts(%q, subdir %q) = (%q, %v), want (%q, %v)", test.channel, test.subdir, canonical, valid, test.canonical, test.valid)
			}
		})
	}
}

func TestLocalChannelMissingChannelDoesNotFallBackToURL(t *testing.T) {
	record := channelRecord("certifi", "2026.7.22", "", "linux-64")
	record.Record.URL = "https://conda.anaconda.org/conda-forge/linux-64/certifi-2026.7.22-build_0.conda"
	if facts, valid := condaChannelFacts(record.Record); facts.identity != "" || valid {
		t.Fatalf("URL must not replace a missing Channel: (%q, %v)", facts.identity, valid)
	}
	if minimum, channel := caPackageMinimum(record.Record); minimum != "" || channel != "" {
		t.Fatalf("missing Channel must stay unknown for CA classification: (%q, %q)", minimum, channel)
	}
}

func TestCAPackageMinimumMeasuredOutputs(t *testing.T) {
	for _, test := range []struct {
		name, pkg, channel, subdir, minimum, source string
	}{
		{"certifi main", "certifi", "https://repo.anaconda.com/pkgs/main", "linux-64", "2026.10.19", "defaults"},
		{"ca-certificates main", "ca-certificates", "https://repo.anaconda.com/pkgs/main/linux-64", "linux-64", "2026.10.20", "defaults"},
		{"certifi forge bare", "certifi", "https://conda.anaconda.org/conda-forge", "linux-64", "2026.10.19", "conda-forge"},
		{"ca-certificates forge explicit", "ca-certificates", "https://conda.anaconda.org/conda-forge/linux-64", "linux-64", "2026.10.19", "conda-forge"},
		{"uppercase main host", "ca-certificates", "https://REPO.ANACONDA.COM/pkgs/main", "linux-64", "2026.10.20", "defaults"},
		{"r is recognized but CA-unknown", "certifi", "https://repo.anaconda.com/pkgs/r", "linux-64", "", ""},
		{"msys2 is recognized but CA-unknown", "certifi", "https://repo.anaconda.com/pkgs/msys2", "win-64", "", ""},
		{"custom canonical but CA-unknown", "certifi", "https://example.test/private/channel", "linux-64", "", ""},
		{"doubled slash is not conda-forge", "certifi", "https://conda.anaconda.org/conda-forge//", "", "", ""},
		{"bare defaults is unknown", "certifi", "defaults", "linux-64", "", ""},
		{"missing channel is unknown", "certifi", "", "linux-64", "", ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			record := channelRecord(test.pkg, "2026.7.22", test.channel, test.subdir)
			minimum, source := caPackageMinimum(record.Record)
			if minimum != test.minimum || source != test.source {
				t.Fatalf("caPackageMinimum = (%q, %q), want (%q, %q)", minimum, source, test.minimum, test.source)
			}
		})
	}
}

func TestChannelOraclesDoNotMutateSourceRecord(t *testing.T) {
	record := channelRecord("ca-certificates", "2026.7.22", "https://secret:password@conda.anaconda.org/conda-forge/linux-64?token=TOKEN", "linux-64")
	before, err := json.Marshal(record.Record)
	if err != nil {
		t.Fatal(err)
	}
	condaChannelFacts(record.Record)
	caPackageMinimum(record.Record)
	after, err := json.Marshal(record.Record)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatalf("channel oracles mutated the source record:\nbefore=%s\nafter=%s", before, after)
	}
}
