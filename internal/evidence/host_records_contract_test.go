package evidence

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

// Baseline oracles for condaRecordsForPrefix. Literal values are the contract:
// 10000 raw conda-meta entries before filtering, 32 MiB per record, 256 MiB per
// prefix collection, and SourceIndex counted over sorted direct-child matches
// (failed records keep their index).

// hostRecordsSparse creates a sparse zero-filled file. Its size is charged by the
// host budget before reading, and it fails parsing, so it isolates budget accounting.
func hostRecordsSparse(t *testing.T, name string, size int64) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(size); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestHostRecordsContractBackslashDocumentGuard(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("backslashes are path separators on Windows")
	}
	prefix := t.TempDir()
	writeMeta(t, prefix, "a\\bad.json", hostRecordJSON("rejected", ""))
	writeMeta(t, prefix, "conda-meta\\accepted.json", hostRecordJSON("accepted", ""))
	writeMeta(t, prefix, "z-good.json", hostRecordJSON("good", ""))
	records, err := condaRecordsForPrefix(context.Background(), prefix)
	if err == nil || !strings.Contains(err.Error(), "a\\bad.json: metadata is not a direct conda-meta document") {
		t.Fatalf("backslash document guard changed: %+v %v", records, err)
	}
	if len(records) != 2 || records[0].Record.Name != "accepted" || records[0].Record.SourceIndex != 1 || records[1].Record.Name != "good" || records[1].Record.SourceIndex != 2 {
		t.Fatalf("failed direct-document guard must consume its sorted index: %+v", records)
	}
}

func TestHostRecordsContractCancellationKeepsEarlierRecords(t *testing.T) {
	prefix := t.TempDir()
	for _, name := range []string{"a", "b"} {
		writeMeta(t, prefix, name+".json", hostRecordJSON(name, ""))
	}
	baseline, err := condaRecordsForPrefix(context.Background(), prefix)
	if err != nil || len(baseline) != 2 {
		t.Fatalf("uncancelled baseline: %+v %v", baseline, err)
	}
	sawEmpty, sawPartial, sawComplete, sawBarePartial := false, false, false, false
	for limit := 0; limit < 100; limit++ {
		ctx := &countdownContext{Context: context.Background(), limit: limit}
		records, err := condaRecordsForPrefix(ctx, prefix)
		if !reflect.DeepEqual(records, baseline[:len(records)]) && len(records) != 0 {
			t.Fatalf("cancellation changed retained records at limit %d: %+v", limit, records)
		}
		if err == nil {
			sawComplete = len(records) == 2
			break
		}
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("unexpected cancellation error at limit %d: %v", limit, err)
		}
		if len(records) == 1 && strings.TrimSpace(strings.ReplaceAll(err.Error(), "context canceled", "")) == "" {
			if err.Error() != "context canceled\ncontext canceled" {
				t.Fatalf("cancellation diagnostics changed at limit %d: %q", limit, err)
			}
			sawBarePartial = true
		}
		sawEmpty = sawEmpty || len(records) == 0
		sawPartial = sawPartial || len(records) == 1
	}
	if !sawEmpty || !sawPartial || !sawComplete || !sawBarePartial {
		t.Fatalf("cancellation sweep missed an outcome: empty=%v partial=%v complete=%v barePartial=%v", sawEmpty, sawPartial, sawComplete, sawBarePartial)
	}
}

func TestHostRecordsContractMixedInventory(t *testing.T) {
	prefix := t.TempDir()
	meta := filepath.Join(prefix, "conda-meta")
	writeMeta(t, prefix, "a-bad.json", `{"name":`)
	writeMeta(t, prefix, "m-good.json", hostRecordJSON("middle", ""))
	writeMeta(t, prefix, "z-good.json", hostRecordJSON("late", `,"files":["bin/late"]`))
	writeMeta(t, prefix, "UPPER.JSON", hostRecordJSON("upper", ""))
	writeMeta(t, prefix, "notes.txt", "not json")
	writeMeta(t, filepath.Join(meta, "sub"), "inner.json", hostRecordJSON("nested", ""))
	if err := os.Mkdir(filepath.Join(meta, "dir.json"), 0o755); err != nil {
		t.Fatal(err)
	}

	records, err := condaRecordsForPrefix(context.Background(), prefix)
	if err == nil || !strings.Contains(err.Error(), "a-bad.json") {
		t.Fatalf("malformed early record must be reported: %v", err)
	}
	for _, excluded := range []string{"UPPER", "dir.json", "inner", "notes"} {
		if strings.Contains(err.Error(), excluded) {
			t.Fatalf("excluded entry %q leaked into error: %v", excluded, err)
		}
	}
	if len(records) != 2 {
		t.Fatalf("records = %d, want 2 good records: %+v", len(records), records)
	}
	for _, record := range records {
		if record.Record.SourcePath != record.Path {
			t.Fatalf("SourcePath %q != Path %q", record.Record.SourcePath, record.Path)
		}
	}
	if records[0].Path != filepath.Join(meta, "m-good.json") || records[0].Record.Name != "middle" ||
		records[0].Record.SourceIndex != 1 || !records[0].OwnershipKnown {
		t.Fatalf("middle record = %+v, want index 1 with explicit empty ownership", records[0])
	}
	if records[1].Path != filepath.Join(meta, "z-good.json") || records[1].Record.Name != "late" ||
		records[1].Record.SourceIndex != 2 || !records[1].OwnershipKnown || len(records[1].Record.Files) != 1 {
		t.Fatalf("late record = %+v, want index 2 with known ownership", records[1])
	}
}

func TestHostRecordsContractLinkedRecordErrorOrder(t *testing.T) {
	prefix := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside.json")
	if err := os.WriteFile(outside, []byte(hostRecordJSON("outside", "")), 0o644); err != nil {
		t.Fatal(err)
	}
	writeMeta(t, prefix, "a-bad.json", `{"name":`)
	writeMeta(t, prefix, "good.json", hostRecordJSON("good", ""))
	if err := os.Symlink(outside, filepath.Join(prefix, "conda-meta", "linked.json")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	records, err := condaRecordsForPrefix(context.Background(), prefix)
	if err == nil {
		t.Fatal("malformed and linked records must be reported")
	}
	msg := err.Error()
	bad, linked := strings.Index(msg, "a-bad.json"), strings.Index(msg, "linked.json is not followed")
	if bad < 0 || linked < 0 || bad > linked {
		t.Fatalf("inventory error must precede enumeration error: %q", msg)
	}
	if len(records) != 1 || records[0].Record.Name != "good" || records[0].Record.SourceIndex != 1 {
		t.Fatalf("earlier failure must not renumber good record: %+v", records)
	}
}

func TestHostRecordsContractReadBudget(t *testing.T) {
	for _, test := range []struct {
		name       string
		sparse     int
		wantRecord bool
	}{
		{"seven full reads leave room for a small record", 7, true},
		{"eighth full read exhausts the 256 MiB budget", 8, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			prefix := t.TempDir()
			for i := 0; i < test.sparse; i++ {
				hostRecordsSparse(t, filepath.Join(prefix, "conda-meta", fmt.Sprintf("a-sparse-%d.json", i)), 32<<20)
			}
			writeMeta(t, prefix, "z-good.json", hostRecordJSON("late", ""))

			records, err := condaRecordsForPrefix(context.Background(), prefix)
			if err == nil || !strings.Contains(err.Error(), "a-sparse-0.json") {
				t.Fatalf("zero-filled sparse records must be reported: %v", err)
			}
			if test.wantRecord {
				if len(records) != 1 || records[0].Record.Name != "late" || records[0].Record.SourceIndex != test.sparse {
					t.Fatalf("late record = %+v, want index %d", records, test.sparse)
				}
				return
			}
			if len(records) != 0 || !strings.Contains(err.Error(), "z-good.json: host metadata read limit exceeded") {
				t.Fatalf("late record survived exhausted budget: records=%+v err=%v", records, err)
			}
		})
	}
}

func TestHostRecordsContractExactAndOverRecordLimit(t *testing.T) {
	prefix := t.TempDir()
	exact := hostRecordJSON("exact", "")
	exact += strings.Repeat(" ", 32<<20-len(exact))
	writeMeta(t, prefix, "a-exact.json", exact)
	hostRecordsSparse(t, filepath.Join(prefix, "conda-meta", "b-over.json"), 32<<20+1)

	records, err := condaRecordsForPrefix(context.Background(), prefix)
	if err == nil || !strings.Contains(err.Error(), "b-over.json") || !strings.Contains(err.Error(), "metadata exceeds 33554432 bytes") {
		t.Fatalf("one byte over the record limit must be rejected by precheck: %v", err)
	}
	if len(records) != 1 || records[0].Record.Name != "exact" || records[0].Record.SourceIndex != 0 {
		t.Fatalf("exact-limit record = %+v, want index 0", records)
	}
}

func TestHostRecordsContractRawEntryCapBeforeFilter(t *testing.T) {
	for _, test := range []struct {
		name      string
		junk      int
		wantError bool
		records   int
	}{
		{"raw total at cap keeps the json record", 9999, false, 1},
		{"raw total over cap fails before json filtering", 10001, true, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			prefix := t.TempDir()
			meta := filepath.Join(prefix, "conda-meta")
			if err := os.MkdirAll(meta, 0o755); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < test.junk; i++ {
				f, err := os.Create(filepath.Join(meta, fmt.Sprintf("x%05d.txt", i)))
				if err != nil {
					t.Fatal(err)
				}
				if err := f.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if test.junk == 9999 {
				writeMeta(t, prefix, "rec.json", hostRecordJSON("only", ""))
			}

			records, err := condaRecordsForPrefix(context.Background(), prefix)
			if test.wantError != (err != nil) || (test.wantError && !strings.Contains(err.Error(), "conda-meta entry limit exceeded (10000)")) {
				t.Fatalf("entry cap error = %v, want error=%v", err, test.wantError)
			}
			if len(records) != test.records {
				t.Fatalf("records = %d, want %d", len(records), test.records)
			}
		})
	}
}
