package evidence

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/conda-incubator/envscout/internal/testimage"
)

func collectSourceIssue(t *testing.T, snapshot Snapshot, source string) Issue {
	t.Helper()
	for _, issue := range snapshot.Issues {
		if issue.Capability == "source" && issue.Path == source {
			return issue
		}
	}
	t.Fatalf("missing source issue for %q in %+v", source, snapshot.Issues)
	return Issue{}
}

func TestCollectDirMatchesCollectHost(t *testing.T) {
	prefix := hostPrefix(t)
	req := Request{Capabilities: []string{"prefixes", "history"}}
	snapshot, err := Collect(context.Background(), "dir", []string{prefix}, "", req)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Targets) != 1 || snapshot.Targets[0].Kind != "dir" || len(snapshot.Targets[0].Prefixes) != 1 {
		t.Fatalf("unexpected dir snapshot: %+v", snapshot)
	}
	if snapshot.Started.IsZero() || snapshot.Targets == nil || snapshot.Issues == nil {
		t.Fatalf("snapshot not initialized: %+v", snapshot)
	}
}

func TestCollectDirNoInputsIsSourceIssue(t *testing.T) {
	snapshot, err := Collect(context.Background(), "dir", nil, "", Request{})
	if err == nil {
		t.Fatal("empty directory input accepted")
	}
	if snapshot.Targets == nil || snapshot.Issues == nil {
		t.Fatalf("nil slices in snapshot: %+v", snapshot)
	}
	collectSourceIssue(t, snapshot, "dir")
}

func TestCollectCancelledContextIsStructuredIncomplete(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, source := range []string{"dir", "oci-archive"} {
		t.Run(source, func(t *testing.T) {
			inputs := []string{hostPrefix(t)}
			platform := ""
			if source == "oci-archive" {
				inputs = []string{testimage.Archive(t, []testimage.Entry{packageMarker("app/conda-meta/python.json", "python")})}
				platform = "linux/amd64"
			}
			snapshot, err := Collect(ctx, source, inputs, platform, Request{Capabilities: []string{"prefixes"}})
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("cancelled collection error = %v", err)
			}
			issue := collectSourceIssue(t, snapshot, source)
			if issue.Message != context.Canceled.Error() {
				t.Fatalf("issue message = %q", issue.Message)
			}
		})
	}
}

// A context can expire after a collector's final check. Collect must not report
// that as a clean snapshot even if the collector returned no error.
func TestCollectDeadlineAfterSuccessIsIncomplete(t *testing.T) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	snapshot, err := Collect(ctx, "dir", []string{hostPrefix(t)}, "", Request{})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expired deadline error = %v", err)
	}
	collectSourceIssue(t, snapshot, "dir")
}

func TestCollectOCIRequiresExactlyOneInput(t *testing.T) {
	archive := testimage.Archive(t, []testimage.Entry{packageMarker("app/conda-meta/python.json", "python")})
	for _, inputs := range [][]string{nil, {}, {archive, archive}} {
		snapshot, err := Collect(context.Background(), "oci-archive", inputs, "linux/amd64", Request{})
		if err == nil {
			t.Fatalf("inputs %v accepted", inputs)
		}
		if len(snapshot.Targets) != 0 {
			t.Fatalf("shape error produced targets: %+v", snapshot.Targets)
		}
		collectSourceIssue(t, snapshot, "oci-archive")
	}
}

func TestCollectUnknownSourceIsRejected(t *testing.T) {
	snapshot, err := Collect(context.Background(), "registry", []string{"x"}, "", Request{})
	if err == nil || snapshot.Targets == nil {
		t.Fatalf("unknown source accepted: %+v, %v", snapshot, err)
	}
	collectSourceIssue(t, snapshot, "registry")
}

func TestCollectOCIBadInputAndPlatform(t *testing.T) {
	archive := testimage.Archive(t, []testimage.Entry{packageMarker("app/conda-meta/python.json", "python")})
	for _, tc := range []struct {
		name, input, platform string
	}{
		{"missing archive", filepath.Join(t.TempDir(), "absent.tar"), "linux/amd64"},
		{"directory instead of archive", t.TempDir(), "linux/amd64"},
		{"missing platform", archive, ""},
		{"wrong platform", archive, "linux/arm64"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			snapshot, err := Collect(context.Background(), "oci-archive", []string{tc.input}, tc.platform, Request{Capabilities: []string{"prefixes"}})
			if err == nil {
				t.Fatal("bad image input accepted")
			}
			if len(snapshot.Targets) != 0 {
				t.Fatalf("load failure produced targets: %+v", snapshot.Targets)
			}
			collectSourceIssue(t, snapshot, "oci-archive")
		})
	}
}

// Successful collection keeps evidence and records partial coverage alongside it.
func TestCollectOCIPartialEvidenceIsPreserved(t *testing.T) {
	// An oversized cache index is an established partial-coverage trigger.
	archive := testimage.Archive(t, []testimage.Entry{
		packageMarker("opt/conda/conda-meta/conda.json", "conda"),
		{Name: "opt/conda/pkgs/pkg.conda", Data: "archive"},
		{Name: "opt/conda/pkgs/broken/info/index.json", Data: strings.Repeat("x", imageMetadataLimit+1)},
	})
	snapshot, err := Collect(context.Background(), "oci-archive", []string{archive}, "linux/amd64", Request{Capabilities: []string{"prefixes", "final-cache"}})
	if err != nil {
		t.Fatalf("partial evidence returned error: %v", err)
	}
	if len(snapshot.Targets) != 1 {
		t.Fatalf("targets = %+v", snapshot.Targets)
	}
	target := snapshot.Targets[0]
	if len(target.Prefixes) != 1 || len(target.Archives) != 1 || target.Kind != "oci-archive" || !strings.HasPrefix(target.ID, "oci:") {
		t.Fatalf("positive evidence lost: %+v", target)
	}
	if target.Coverage["final-cache"] != Partial || target.Coverage["prefixes"] != Complete {
		t.Fatalf("coverage = %+v", target.Coverage)
	}
}

// Cleanup runs on every path: the staged layout must not survive a collection.
func TestCollectOCIReleasesStagingOnCollectionError(t *testing.T) {
	parent := t.TempDir()
	t.Setenv("TMPDIR", parent)
	t.Setenv("TMP", parent)
	t.Setenv("TEMP", parent)
	archive := testimage.Archive(t, []testimage.Entry{packageMarker("app/conda-meta/python.json", "python")})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cancel()
	if _, err := Collect(ctx, "oci-archive", []string{archive}, "linux/amd64", Request{Capabilities: []string{"prefixes"}}); err == nil {
		t.Fatal("cancelled archive collection succeeded")
	}
	if entries, err := os.ReadDir(parent); err != nil || len(entries) != 0 {
		t.Fatalf("staging leaked after cancelled collection: %+v, %v", entries, err)
	}
}

func TestCollectOCISuccessReleasesStaging(t *testing.T) {
	parent := t.TempDir()
	t.Setenv("TMPDIR", parent)
	t.Setenv("TMP", parent)
	t.Setenv("TEMP", parent)
	archive := testimage.Archive(t, []testimage.Entry{packageMarker("app/conda-meta/python.json", "python")})
	if _, err := Collect(context.Background(), "oci-archive", []string{archive}, "linux/amd64", Request{Capabilities: []string{"prefixes"}}); err != nil {
		t.Fatal(err)
	}
	if entries, err := os.ReadDir(parent); err != nil || len(entries) != 0 {
		t.Fatalf("staging leaked after successful collection: %+v, %v", entries, err)
	}
}
