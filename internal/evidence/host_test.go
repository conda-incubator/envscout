package evidence

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/anaconda/envscout/internal/discovery"
)

func hostPrefix(t *testing.T) string {
	t.Helper()
	prefix := filepath.Join(t.TempDir(), "env")
	meta := filepath.Join(prefix, "conda-meta")
	if err := os.MkdirAll(meta, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(meta, "pkg.json"), []byte(`{"name":"demo","version":"1"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(meta, "history"), []byte("==> initial <==\n==> update <==\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return prefix
}

func TestCollectHostAndProject(t *testing.T) {
	prefix := hostPrefix(t)
	project := t.TempDir()
	var resolveErr error
	project, resolveErr = filepath.EvalSymlinks(project)
	if resolveErr != nil {
		t.Fatal(resolveErr)
	}
	request := Request{Capabilities: []string{"prefixes", "history", "project-association"}, Project: project}
	snapshot, err := CollectHost(context.Background(), []string{prefix, prefix}, request, nil)
	if err != nil || len(snapshot.Targets) != 1 || snapshot.Targets[0].Prefixes[0].Revision == nil || *snapshot.Targets[0].Prefixes[0].Revision != 1 {
		t.Fatalf("unexpected host evidence: %+v, %v", snapshot, err)
	}
	target := snapshot.Targets[0]
	if target.Project == nil || !target.Project.Associated || target.Project.LockPath != "" || !strings.HasPrefix(target.ID, "file:") {
		t.Fatalf("missing explicit association: %+v", target)
	}
	if err := os.WriteFile(filepath.Join(project, "pixi.lock"), []byte("version: 6"), 0o644); err != nil {
		t.Fatal(err)
	}
	snapshot, err = CollectHost(context.Background(), []string{prefix}, request, nil)
	if err != nil || snapshot.Targets[0].Project.LockVerified || snapshot.Targets[0].Project.LockPath == "" {
		t.Fatalf("lock presence claimed verification: %+v, %v", snapshot, err)
	}
}

func TestHostContextAndAmbiguousAssociation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := CollectHost(ctx, []string{hostPrefix(t)}, Request{}, nil); err == nil {
		t.Fatal("cancelled collection succeeded")
	}
	if _, err := CollectHost(context.Background(), []string{hostPrefix(t), hostPrefix(t)}, Request{Capabilities: []string{"project-association"}, Project: t.TempDir()}, nil); err == nil {
		t.Fatal("ambiguous project association accepted")
	}
}

func TestDisabledHistoryDoesNotInspectInvalidHistory(t *testing.T) {
	prefix := hostPrefix(t)
	history := filepath.Join(prefix, "conda-meta", "history")
	if err := os.Remove(history); err != nil {
		t.Fatal(err)
	}
	// A directory is invalid history but must be irrelevant to EC004-only lint.
	if err := os.Mkdir(history, 0o755); err != nil {
		t.Fatal(err)
	}
	snapshot, err := CollectHost(context.Background(), []string{prefix}, Request{Capabilities: []string{"prefixes", "project-association"}}, nil)
	if err != nil || len(snapshot.Issues) != 0 || snapshot.Targets[0].Coverage["history"] != NotCollected || snapshot.Targets[0].Prefixes[0].Revision != nil {
		t.Fatalf("unrequested history affected lint: %+v %v", snapshot, err)
	}
	snapshot, err = CollectHost(context.Background(), []string{prefix}, Request{Capabilities: []string{"prefixes", "history"}}, nil)
	if err != nil || len(snapshot.Issues) == 0 || snapshot.Issues[0].Capability != "history" || snapshot.Targets[0].Coverage["prefixes"] != Complete {
		t.Fatalf("history error not independently reported: %+v %v", snapshot, err)
	}
}

type cancelAfterFinding struct {
	context.Context
	progress *discovery.Progress
}

func (c cancelAfterFinding) Err() error {
	if c.progress.Environments.Load() > 0 {
		return context.Canceled
	}
	return nil
}

func TestHostCancellationPreservesPartialFindings(t *testing.T) {
	prefix := hostPrefix(t)
	progress := new(discovery.Progress)
	ctx := cancelAfterFinding{context.Background(), progress}
	snapshot, err := CollectHost(ctx, []string{prefix}, Request{Capabilities: []string{"prefixes", "history"}}, progress)
	if err == nil || len(snapshot.Targets) != 1 || len(snapshot.Targets[0].Prefixes) != 1 || snapshot.Targets[0].Coverage["prefixes"] != Partial {
		t.Fatalf("cancelled collection lost partial facts: %+v, %v", snapshot, err)
	}
}

func TestHostNoCollectorsDeduplicatesRoots(t *testing.T) {
	prefix := hostPrefix(t)
	snapshot, err := CollectHost(context.Background(), []string{prefix, prefix}, Request{}, nil)
	if err != nil || len(snapshot.Targets) != 1 {
		t.Fatalf("empty-capability roots not deduplicated: %+v %v", snapshot, err)
	}
}
