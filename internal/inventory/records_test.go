package inventory

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	stereofile "github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/source"
	"github.com/anchore/syft/syft/source/directorysource"
)

func canonicalRecordJSON(name, version string) string {
	return `{"name":"` + name + `","version":"` + version + `","build":"0","build_number":0,"subdir":"linux-64","fn":"` + name + `-` + version + `-0.conda","url":"https://example.com/linux-64/` + name + `-` + version + `-0.conda"}`
}

func TestCondaRecordsRequiresCanonicalMetadata(t *testing.T) {
	root := condaFixture(t, map[string]string{
		"good.json":   canonicalRecordJSON("good", "1.0"),
		"sparse.json": `{"name":"sparse","version":"1.0"}`,
	})
	src, err := directorysource.NewFromPath(root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = src.Close() }()
	records, err := CondaRecords(context.Background(), src, source.SquashedScope)
	if err == nil || !strings.Contains(err.Error(), "sparse.json") || len(records) != 1 {
		t.Fatalf("canonical records must preserve good and reject sparse: records=%+v err=%v", records, err)
	}
}

func TestCondaRecordsOwnershipPresence(t *testing.T) {
	for _, test := range []struct {
		name, fields   string
		known, invalid bool
	}{
		{"absent", "", false, false},
		{"files null", `,"files":null`, false, true},
		{"files empty", `,"files":[]`, true, false},
		{"files populated", `,"files":["bin/good"]`, true, false},
		{"paths data null", `,"paths_data":null`, false, true},
		{"paths omitted", `,"paths_data":{"paths_version":1}`, false, false},
		{"paths null", `,"paths_data":{"paths_version":1,"paths":null}`, false, true},
		{"paths empty", `,"paths_data":{"paths_version":1,"paths":[]}`, true, false},
		{"paths populated", `,"paths_data":{"paths_version":1,"paths":[{"_path":"bin/good","path_type":"hardlink"}]}`, true, false},
		{"unknown uppercase key", `,"FILES":[]`, false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			document := strings.TrimSuffix(canonicalRecordJSON("good", "1.0"), "}") + test.fields + "}"
			src, err := directorysource.NewFromPath(condaFixture(t, map[string]string{"good.json": document}))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = src.Close() }()
			records, err := CondaRecords(context.Background(), src, source.SquashedScope)
			if test.invalid {
				if err == nil || len(records) != 0 {
					t.Fatalf("invalid null ownership must remain rejected: records=%+v err=%v", records, err)
				}
				return
			}
			if err != nil || len(records) != 1 || records[0].OwnershipKnown != test.known {
				t.Fatalf("ownership known=%v: records=%+v err=%v", test.known, records, err)
			}
		})
	}
}

func TestCondaRecordsAcceptsLargeRealisticFilesList(t *testing.T) {
	const count = 60000
	files := make([]string, 0, count)
	for i := 0; i < count; i++ {
		files = append(files, "lib/python3.12/site-packages/pkg/module_"+strconv.Itoa(i)+".py")
	}
	encoded, err := json.Marshal(files)
	if err != nil {
		t.Fatal(err)
	}
	document := strings.TrimSuffix(canonicalRecordJSON("big", "1.0"), "}") + `,"files":` + string(encoded) + "}"
	if len(document) < 2<<20 || len(document) > CondaRecordByteLimit {
		t.Fatalf("synthetic record size %d outside the 2 MiB..%d-byte range", len(document), CondaRecordByteLimit)
	}
	src, err := directorysource.NewFromPath(condaFixture(t, map[string]string{"big.json": document}))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = src.Close() }()
	records, err := CondaRecords(context.Background(), src, source.SquashedScope)
	if err != nil || len(records) != 1 || len(records[0].Record.Files) != len(files) || !records[0].OwnershipKnown {
		t.Fatalf("valid large record rejected: records=%d err=%v", len(records), err)
	}
}

func TestCondaRecordsBoundsMetadata(t *testing.T) {
	root := condaFixture(t, map[string]string{
		"good.json":  canonicalRecordJSON("good", "1.0"),
		"large.json": canonicalRecordJSON("large", "1.0") + strings.Repeat(" ", CondaRecordByteLimit),
	})
	src, err := directorysource.NewFromPath(root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = src.Close() }()
	records, err := CondaRecords(context.Background(), src, source.SquashedScope)
	if err == nil || !strings.Contains(err.Error(), "large.json") || len(records) != 1 {
		t.Fatalf("oversized metadata must preserve good and return coverage error: records=%+v err=%v", records, err)
	}
}

func TestCondaRecordsRetainsCanonicalFieldsAndSource(t *testing.T) {
	document := strings.TrimSuffix(canonicalRecordJSON("good", "1.0"), "}") + `,"requested_specs":["good >=1"],"files":["bin/good"],"paths_data":{"paths_version":1,"paths":[{"_path":"bin/good","original_path":"bin/old","path_type":"hardlink","no_link":true,"size_in_bytes":10}]}}`
	root := condaFixture(t, map[string]string{"a-good.json": document, "b-bad.json": "{"})
	src, err := directorysource.NewFromPath(root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = src.Close() }()
	records, err := CondaRecords(context.Background(), src, source.SquashedScope)
	if err == nil || len(records) != 1 {
		t.Fatalf("mixed records=%+v err=%v", records, err)
	}
	record := records[0]
	if record.Record.SourceIndex != 0 || record.Record.SourcePath != record.Path || len(record.Record.RequestedSpecs) != 1 || len(record.Record.Files) != 1 || len(record.Record.PathsData.Paths) != 1 {
		t.Fatalf("canonical metadata or source lost: %+v", record)
	}
	entry := record.Record.PathsData.Paths[0]
	if entry.OriginalPath != "bin/old" || !entry.NoLink || entry.SizeInBytes == nil || *entry.SizeInBytes != 10 {
		t.Fatalf("rattler-only path fields lost: %+v", entry)
	}
}

func TestCondaRecordsNeverReadsAlias(t *testing.T) {
	root := condaFixture(t, map[string]string{"good.json": canonicalRecordJSON("good", "1.0")})
	if err := os.Symlink("good.json", filepath.Join(root, "conda-meta", "alias.json")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	src, err := directorysource.NewFromPath(root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = src.Close() }()
	resolver, err := src.FileResolver(source.SquashedScope)
	if err != nil {
		t.Fatal(err)
	}
	locations, err := resolver.FilesByGlob("**/conda-meta/*.json")
	if err != nil {
		t.Fatal(err)
	}
	// Pin rejection even when a resolver chooses the alias as its best match.
	alias := locations[0]
	alias.AccessPath = "conda-meta/alias.json"
	guard := &recordTestResolver{Resolver: resolver, locations: []file.Location{alias}}
	records, err := CondaRecords(context.Background(), recordTestSource{Source: src, resolver: guard}, source.SquashedScope)
	if err == nil || len(records) != 0 || guard.opened != 0 {
		t.Fatalf("alias was accepted/read: records=%+v err=%v opens=%d", records, err, guard.opened)
	}
}

func TestCondaRecordsCancellationPreservesEarlierRecordsAndCloses(t *testing.T) {
	root := condaFixture(t, map[string]string{
		"a.json": canonicalRecordJSON("a", "1.0"),
		"b.json": canonicalRecordJSON("b", "1.0"),
	})
	src, err := directorysource.NewFromPath(root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = src.Close() }()
	resolver, err := src.FileResolver(source.SquashedScope)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	guard := &recordTestResolver{Resolver: resolver, cancel: cancel}
	records, err := CondaRecords(ctx, recordTestSource{Source: src, resolver: guard}, source.SquashedScope)
	if !errors.Is(err, context.Canceled) || len(records) != 1 || records[0].Record.Name != "a" || guard.closed != 2 {
		t.Fatalf("partial evidence/cancellation/close lost: records=%+v err=%v closed=%d", records, err, guard.closed)
	}
}

func TestCondaRecordsRejectsNonregularAndActualReadOverflow(t *testing.T) {
	root := condaFixture(t, map[string]string{"good.json": canonicalRecordJSON("good", "1.0")})
	src, err := directorysource.NewFromPath(root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = src.Close() }()
	resolver, err := src.FileResolver(source.SquashedScope)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		kind   stereofile.Type
		data   string
		opened int
	}{
		{"nonregular", stereofile.TypeSymLink, "", 0},
		{"actual read overflow", stereofile.TypeRegular, strings.Repeat("x", CondaRecordByteLimit+1), 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			metadata := file.Metadata{FileInfo: stereofile.ManualInfo{ModeValue: 0o644}, Type: test.kind}
			guard := &recordTestResolver{Resolver: resolver, metadata: &metadata, data: test.data}
			records, err := CondaRecords(context.Background(), recordTestSource{Source: src, resolver: guard}, source.SquashedScope)
			if err == nil || len(records) != 0 || guard.opened != test.opened || guard.closed != test.opened {
				t.Fatalf("invalid metadata read/close: records=%+v err=%v opened=%d closed=%d", records, err, guard.opened, guard.closed)
			}
		})
	}
}

type recordTestSource struct {
	source.Source
	resolver file.Resolver
}

func (s recordTestSource) FileResolver(source.Scope) (file.Resolver, error) {
	return s.resolver, nil
}

type recordTestResolver struct {
	file.Resolver
	locations      []file.Location
	metadata       *file.Metadata
	data           string
	cancel         context.CancelFunc
	opened, closed int
}

func (r *recordTestResolver) FileMetadataByLocation(location file.Location) (file.Metadata, error) {
	if r.metadata != nil {
		return *r.metadata, nil
	}
	return r.Resolver.FileMetadataByLocation(location)
}

func (r *recordTestResolver) FilesByGlob(patterns ...string) ([]file.Location, error) {
	if r.locations != nil {
		return r.locations, nil
	}
	return r.Resolver.FilesByGlob(patterns...)
}

func (r *recordTestResolver) FileContentsByLocation(location file.Location) (io.ReadCloser, error) {
	r.opened++
	if r.data != "" {
		return recordTestReader{ReadCloser: io.NopCloser(strings.NewReader(r.data)), resolver: r}, nil
	}
	reader, err := r.Resolver.FileContentsByLocation(location)
	if err != nil {
		return nil, err
	}
	return recordTestReader{ReadCloser: reader, resolver: r}, nil
}

type recordTestReader struct {
	io.ReadCloser
	resolver *recordTestResolver
}

func (r recordTestReader) Read(p []byte) (int, error) {
	if r.resolver.opened == 2 && r.resolver.cancel != nil {
		r.resolver.cancel()
	}
	return r.ReadCloser.Read(p)
}

func (r recordTestReader) Close() error {
	r.resolver.closed++
	return r.ReadCloser.Close()
}
