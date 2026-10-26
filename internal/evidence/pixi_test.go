package evidence

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

const hostPixiLock = `version: 4
environments:
  selected:
    channels:
    - url: https://conda.anaconda.org/conda-forge/
    packages:
      linux-64:
      - conda: https://conda.anaconda.org/conda-forge/linux-64/demo-1-0.conda
packages:
- kind: conda
  name: demo
  version: '1'
  build: '0'
  subdir: linux-64
  url: https://conda.anaconda.org/conda-forge/linux-64/demo-1-0.conda
`

func hostPixiMarker(t *testing.T, prefix, project, subdir string) {
	t.Helper()
	data, err := json.Marshal(map[string]any{"manifest_path": filepath.Join(project, "pixi.toml"), "environment_name": "selected", "resolved_platform": map[string]string{"subdir": subdir}})
	if err != nil {
		t.Fatal(err)
	}
	hostWrite(t, filepath.Join(prefix, "conda-meta/pixi"), string(data))
}

func TestHostInstalledLockExplicitProjectMustMatchMarker(t *testing.T) {
	prefix := hostPrefix(t)
	project := t.TempDir()
	hostWrite(t, filepath.Join(project, "pixi.lock"), hostPixiLock)
	hostPixiMarker(t, prefix, project, "linux-64")
	snapshot, err := CollectHost(context.Background(), []string{prefix}, Request{Capabilities: []string{"installed-lock", "project-association"}, Project: t.TempDir()})
	if err != nil || snapshot.Targets[0].Coverage["installed-lock"] != Partial || snapshot.Targets[0].Lock == nil || snapshot.Targets[0].Lock.Report != nil {
		t.Fatalf("wrong project used for installed comparison: %+v %v", snapshot, err)
	}
}

func TestHostInstalledLockRetainsMismatchAlongsideUnknown(t *testing.T) {
	prefix := hostPrefix(t)
	project := t.TempDir()
	lock := strings.Replace(hostPixiLock, "  subdir: linux-64\n", "  subdir: linux-64\n  sha256: '"+strings.Repeat("1", 64)+"'\n", 1)
	hostWrite(t, filepath.Join(project, "pixi.lock"), lock)
	hostPixiMarker(t, prefix, project, "linux-64")
	writeMeta(t, prefix, "extra.json", hostRecordJSON("extra", ""))
	snapshot, err := CollectHost(context.Background(), []string{prefix}, Request{Capabilities: []string{"installed-lock"}})
	if err != nil {
		t.Fatal(err)
	}
	target := snapshot.Targets[0]
	if target.Lock == nil || target.Lock.Report == nil || len(target.Lock.Report.Extra) != 1 || len(target.Lock.Report.Unknown) == 0 || target.Coverage["installed-lock"] != Partial {
		t.Fatalf("mismatch/unknown evidence lost: %+v", target)
	}
}

func TestHostInstalledLockNoMarkerIsNotApplicable(t *testing.T) {
	snapshot, err := CollectHost(context.Background(), []string{hostPrefix(t)}, Request{Capabilities: []string{"installed-lock"}})
	if err != nil || snapshot.Targets[0].Lock != nil || snapshot.Targets[0].Coverage["installed-lock"] != Complete {
		t.Fatalf("no marker is not an unknown comparison: %+v %v", snapshot, err)
	}
}

func TestHostInstalledLockMarkerSelectsEnvironmentAndPlatform(t *testing.T) {
	prefix := hostPrefix(t)
	project := t.TempDir()
	hostWrite(t, filepath.Join(project, "pixi.lock"), hostPixiLock)
	hostPixiMarker(t, prefix, project, "linux-64")
	snapshot, err := CollectHost(context.Background(), []string{prefix}, Request{Capabilities: []string{"installed-lock", "project-association"}})
	if err != nil {
		t.Fatal(err)
	}
	target := snapshot.Targets[0]
	if target.Lock == nil || target.Lock.Report == nil || !target.Lock.Report.Matches || target.Lock.Report.Scope != "conda" || target.Lock.Environment != "selected" || target.Lock.Subdir != "linux-64" || target.Project != nil {
		t.Fatalf("marker selection/metadata-only sync = %+v", target)
	}
}

func TestHostInstalledLockNeverGuessesOrComparesPartialRecords(t *testing.T) {
	for _, test := range []struct {
		name, subdir string
		broken       bool
	}{
		{"missing-platform", "", false},
		{"unsupported-platform", "not-a-platform", false},
		{"supported-platform-absent-from-lock", "osx-arm64", false},
		{"partial-records", "linux-64", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			prefix := hostPrefix(t)
			project := t.TempDir()
			hostWrite(t, filepath.Join(project, "pixi.lock"), hostPixiLock)
			hostPixiMarker(t, prefix, project, test.subdir)
			if test.broken {
				writeMeta(t, prefix, "broken.json", `{"name":"broken"}`)
			}
			snapshot, err := CollectHost(context.Background(), []string{prefix}, Request{Capabilities: []string{"installed-lock"}})
			if err != nil {
				t.Fatal(err)
			}
			target := snapshot.Targets[0]
			if target.Coverage["installed-lock"] != Partial || target.Lock == nil || target.Lock.Report != nil || target.Lock.Reason == "" {
				t.Fatalf("unsupported/partial evidence compared: %+v", target)
			}
		})
	}
}
