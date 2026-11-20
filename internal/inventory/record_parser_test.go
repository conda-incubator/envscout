package inventory

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	gorattler "github.com/conda-incubator/go-rattler"
)

// parserCanonicalJSON reuses the canonical fixture shape and appends extra
// top-level fields, keeping the JSON valid for every case.
func parserCanonicalJSON(extra string) []byte {
	return []byte(strings.TrimSuffix(canonicalRecordJSON("good", "1.0"), "}") + extra + "}")
}

func TestParseCondaRecordOwnershipPresence(t *testing.T) {
	for _, test := range []struct {
		name, extra string
		known       bool
		invalid     bool
		files       int
	}{
		{name: "omitted", extra: ``, known: false},
		{name: "files empty", extra: `,"files":[]`, known: true},
		{name: "files populated", extra: `,"files":["bin/good"]`, known: true, files: 1},
		{name: "paths data omitted paths", extra: `,"paths_data":{"paths_version":1}`, known: false},
		{name: "paths data empty paths", extra: `,"paths_data":{"paths_version":1,"paths":[]}`, known: true},
		{name: "paths data populated", extra: `,"paths_data":{"paths_version":1,"paths":[{"_path":"bin/good","path_type":"hardlink"}]}`, known: true},
		{name: "files null", extra: `,"files":null`, invalid: true},
		{name: "paths data null", extra: `,"paths_data":null`, invalid: true},
		{name: "paths null", extra: `,"paths_data":{"paths_version":1,"paths":null}`, invalid: true},
		{name: "uppercase FILES absent", extra: `,"FILES":[]`, known: false},
		{name: "uppercase FILES populated", extra: `,"FILES":["bin/good"]`, known: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			data := parserCanonicalJSON(test.extra)
			if !json.Valid(data) {
				t.Fatal("ownership fixture must be valid JSON")
			}
			got, err := ParseCondaRecord(data)
			if test.invalid {
				if err == nil || !reflect.DeepEqual(got, CondaRecord{}) {
					t.Fatalf("invalid ownership must return zero record and error: got=%+v err=%v", got, err)
				}
				return
			}
			if err != nil || got.OwnershipKnown != test.known || len(got.Record.Files) != test.files {
				t.Fatalf("known=%v files=%d: got=%+v err=%v", test.known, test.files, got, err)
			}
		})
	}
}

func TestParseCondaRecordRejectsMalformedAndSparse(t *testing.T) {
	for _, data := range []string{
		`{`,
		`{"name":"sparse","version":"1.0"}`,
	} {
		got, err := ParseCondaRecord([]byte(data))
		if err == nil || !reflect.DeepEqual(got, CondaRecord{}) {
			t.Fatalf("%q must return zero record and error: got=%+v err=%v", data, got, err)
		}
	}
}

func TestParseCondaRecordCanonicalFieldsMatchRattler(t *testing.T) {
	data := parserCanonicalJSON(`,"requested_specs":["good >=1"],"files":["bin/good"],"paths_data":{"paths_version":1,"paths":[{"_path":"bin/good","original_path":"bin/old","path_type":"hardlink","no_link":true,"size_in_bytes":10}]}`)
	before := append([]byte(nil), data...)

	got, err := ParseCondaRecord(data)
	if err != nil {
		t.Fatal(err)
	}
	want, err := gorattler.ParsePrefixRecord(data)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Record, want) {
		t.Fatalf("parser diverged from rattler:\ngot  %+v\nwant %+v", got.Record, want)
	}
	// Literal checks guard against a shared-helper mistake masking a field change.
	if got.Record.Name != "good" || got.Record.Version != "1.0" || got.Record.Filename != "good-1.0-0.conda" {
		t.Fatalf("identity fields: %+v", got.Record)
	}
	if !reflect.DeepEqual(got.Record.RequestedSpecs, []string{"good >=1"}) || !reflect.DeepEqual(got.Record.Files, []string{"bin/good"}) {
		t.Fatalf("specs/files: %+v", got.Record)
	}
	entry := got.Record.PathsData.Paths[0]
	if entry.OriginalPath != "bin/old" || !entry.NoLink || entry.SizeInBytes == nil || *entry.SizeInBytes != 10 {
		t.Fatalf("rattler-only path fields lost: %+v", entry)
	}
	if got.Record.Link != nil {
		t.Fatalf("absent link must stay nil: %+v", got.Record.Link)
	}
	if !bytes.Equal(data, before) {
		t.Fatal("input bytes mutated")
	}
}

func TestParseCondaRecordIsDeterministicAndSourceless(t *testing.T) {
	// Source attribution is set by CondaRecords, never by parsing. Keys that
	// look like attribution must not become record metadata.
	data := parserCanonicalJSON(`,"source_index":7,"source_path":"/host/conda-meta/x.json"`)
	before := append([]byte(nil), data...)

	first, err := ParseCondaRecord(data)
	if err != nil {
		t.Fatal(err)
	}
	second, err := ParseCondaRecord(data)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("parse not deterministic: %+v != %+v", first, second)
	}
	if first.Record.SourceIndex != 0 || first.Record.SourcePath != "" || first.Path != "" {
		t.Fatalf("parser attributed source: %+v", first)
	}
	if !bytes.Equal(data, before) {
		t.Fatal("input bytes mutated")
	}
}

func TestParseCondaRecordRawJSONSanity(t *testing.T) {
	// Pin the fixture itself so a helper change cannot silently alter the cases above.
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(parserCanonicalJSON(""), &fields); err != nil {
		t.Fatal(err)
	}
	if _, ok := fields["files"]; ok {
		t.Fatal("canonical fixture must omit files")
	}
}
