package cli

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestScanProgressDoesNotChangeJSONOrSerialOptions(t *testing.T) {
	root := condaRoot(t)
	venvFixture(t, root, "venv", true)
	stdout, stderr, err := runCLI(t, context.Background(), "scan", "--format", "json", "--output-dir", t.TempDir(), root)
	if err != nil || stderr != "" || !json.Valid([]byte(stdout)) || strings.Contains(stdout, "Creating SBOMs:") {
		t.Fatalf("noninteractive scan must retain one JSON report and no display output: %v\n%s\n%s", err, stdout, stderr)
	}
	var report struct {
		Status       string            `json:"status"`
		Observations []json.RawMessage `json:"observations"`
	}
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatal(err)
	}
	if report.Status != "complete" || len(report.Observations) != 2 {
		t.Fatalf("progress must not change scan observations: %s", stdout)
	}
	if New().PersistentFlags().Lookup("jobs") != nil {
		t.Fatal("progress-only implementation must not introduce a concurrency flag")
	}
}
