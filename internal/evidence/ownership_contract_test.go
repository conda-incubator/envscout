package evidence

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/conda-incubator/envscout/internal/inventory"
	gorattler "github.com/conda-incubator/go-rattler"
)

// Oracles for collectHostPython ownership: a distribution is owned only by a
// single conda record name claiming its METADATA path; conflicting owners mark it
// ambiguous (sticky, source-order independent); unknown ownership is Partial.
const ownershipMetadata = "lib/python3.12/site-packages/demo-1.dist-info/METADATA"

const ownershipAmbiguous = "distribution metadata has multiple conda owners"

const ownershipUnavailable = "conda file ownership metadata is unavailable"

func ownershipFixture(t *testing.T) string {
	t.Helper()
	prefix, err := filepath.EvalSymlinks(hostPrefix(t))
	if err != nil {
		t.Fatal(err)
	}
	hostWrite(t, filepath.Join(prefix, filepath.FromSlash(ownershipMetadata)), "Metadata-Version: 2.1\nName: demo\nVersion: 1\n")
	return prefix
}

func ownershipFiles(paths ...string) string {
	encoded, _ := json.Marshal(paths)
	return `,"files":` + string(encoded)
}

func ownershipPathsData(paths ...string) string {
	type entry struct {
		Path string `json:"_path"`
		Type string `json:"path_type"`
	}
	entries := make([]entry, 0, len(paths))
	for _, p := range paths {
		entries = append(entries, entry{Path: p, Type: "hardlink"})
	}
	encoded, _ := json.Marshal(map[string]any{"paths_version": 1, "paths": entries})
	return `,"paths_data":` + string(encoded)
}

// ownershipCollect runs the real CollectHost path and checks record-level invariants.
func ownershipCollect(t *testing.T, prefix string, wantRecords int) Target {
	t.Helper()
	snapshot, err := CollectHost(context.Background(), []string{prefix}, Request{Capabilities: []string{"conda-records", "python-distributions"}})
	if err != nil || len(snapshot.Targets) != 1 || len(snapshot.Targets[0].Prefixes) != 1 {
		t.Fatalf("collection = %+v, %v", snapshot, err)
	}
	target := snapshot.Targets[0]
	prefixState := target.Prefixes[0]
	if len(prefixState.Records) != wantRecords || prefixState.RecordCoverage != Complete || target.Coverage["conda-records"] != Complete {
		t.Fatalf("record invariant broken: %+v", target)
	}
	for _, record := range prefixState.Records {
		if record.Record.Name == "" || record.Record.SourcePath != record.Path {
			t.Fatalf("invalid canonical record: %+v", record)
		}
	}
	return target
}

func ownershipOnlyDist(t *testing.T, target Target) PythonDistribution {
	t.Helper()
	if len(target.Python) != 1 {
		t.Fatalf("python distributions = %+v", target.Python)
	}
	return target.Python[0]
}

func ownershipIssues(target Target, message string) []Issue {
	var found []Issue
	for _, issue := range target.Issues {
		if issue.Message == message {
			found = append(found, issue)
		}
	}
	return found
}

// ownershipSynthetic bypasses canonical parsing to exercise states the parser cannot
// produce (empty names, OwnershipKnown=false with claims).
func ownershipSynthetic(name string, known bool, files ...string) inventory.CondaRecord {
	return inventory.CondaRecord{Path: filepath.Join("conda-meta", name+".json"), OwnershipKnown: known, Record: gorattler.PrefixRecord{
		PackageRecord: gorattler.PackageRecord{Name: name, Version: "1"}, Files: files,
	}}
}

func ownershipCollectSynthetic(t *testing.T, prefix string, records ...inventory.CondaRecord) Target {
	t.Helper()
	target := Target{ID: "synthetic", Kind: "dir", Prefixes: []Prefix{{Path: prefix, Records: records, RecordCoverage: Complete}},
		Coverage: map[string]string{CapPythonDistributions: Complete}, Issues: []Issue{}}
	collectHostPython(context.Background(), &target, target.Prefixes[0])
	return target
}

func TestOwnershipContractRepeatedSameOwnerIsComplete(t *testing.T) {
	prefix := ownershipFixture(t)
	// a.json claims METADATA through both Files and PathsData; the duplicate must not self-conflict.
	writeMeta(t, prefix, "a.json", hostRecordJSON("demo", ownershipFiles(ownershipMetadata)+ownershipPathsData(ownershipMetadata)))
	writeMeta(t, prefix, "b.json", hostRecordJSON("demo", ownershipFiles(ownershipMetadata)))
	target := ownershipCollect(t, prefix, 3)
	dist := ownershipOnlyDist(t, target)
	if dist.OwnedBy != "demo" || target.Coverage[CapPythonDistributions] != Complete || len(target.Issues) != 0 {
		t.Fatalf("same-owner claims = %+v", target)
	}
}

func TestOwnershipContractDifferentOwnersAreAmbiguous(t *testing.T) {
	prefix := ownershipFixture(t)
	writeMeta(t, prefix, "a.json", hostRecordJSON("alpha", ownershipFiles(ownershipMetadata)))
	writeMeta(t, prefix, "b.json", hostRecordJSON("beta", ownershipFiles(ownershipMetadata)))
	target := ownershipCollect(t, prefix, 3)
	if dist := ownershipOnlyDist(t, target); dist.OwnedBy != "" {
		t.Fatalf("ambiguous owner leaked = %+v", dist)
	}
	issues := ownershipIssues(target, ownershipAmbiguous)
	if target.Coverage[CapPythonDistributions] != Partial || len(issues) != 1 || issues[0].Path != filepath.Join(prefix, filepath.FromSlash(ownershipMetadata)) {
		t.Fatalf("ambiguity issues = %+v, target %+v", issues, target)
	}
}

func TestOwnershipContractSourceOrderAmbiguityIsSticky(t *testing.T) {
	prefix := ownershipFixture(t)
	writeMeta(t, prefix, "a.json", hostRecordJSON("alpha", ownershipFiles(ownershipMetadata)))
	writeMeta(t, prefix, "b.json", hostRecordJSON("beta", ownershipFiles(ownershipMetadata)))
	writeMeta(t, prefix, "c.json", hostRecordJSON("alpha", ownershipFiles(ownershipMetadata)))
	target := ownershipCollect(t, prefix, 4)
	names := []string{}
	for _, record := range target.Prefixes[0].Records {
		names = append(names, record.Record.Name)
	}
	if len(names) != 4 || names[0] != "alpha" || names[1] != "beta" || names[2] != "alpha" {
		t.Fatalf("source order = %v", names)
	}
	if dist := ownershipOnlyDist(t, target); dist.OwnedBy != "" || len(ownershipIssues(target, ownershipAmbiguous)) != 1 || target.Coverage[CapPythonDistributions] != Partial {
		t.Fatalf("A,B,A ownership = %+v, target %+v", dist, target)
	}
}

func TestOwnershipContractAbsoluteAndRelativeClaimsCollapse(t *testing.T) {
	absolute := func(prefix string) string { return filepath.Join(prefix, filepath.FromSlash(ownershipMetadata)) }
	t.Run("same owner", func(t *testing.T) {
		prefix := ownershipFixture(t)
		writeMeta(t, prefix, "a.json", hostRecordJSON("alpha", ownershipFiles(absolute(prefix))))
		writeMeta(t, prefix, "b.json", hostRecordJSON("alpha", ownershipPathsData(ownershipMetadata)))
		target := ownershipCollect(t, prefix, 3)
		if dist := ownershipOnlyDist(t, target); dist.OwnedBy != "alpha" || len(target.Issues) != 0 {
			t.Fatalf("absolute and relative same-owner claims = %+v", target)
		}
	})
	t.Run("different owners", func(t *testing.T) {
		prefix := ownershipFixture(t)
		writeMeta(t, prefix, "a.json", hostRecordJSON("alpha", ownershipFiles(absolute(prefix))))
		writeMeta(t, prefix, "b.json", hostRecordJSON("beta", ownershipPathsData(ownershipMetadata)))
		target := ownershipCollect(t, prefix, 3)
		if dist := ownershipOnlyDist(t, target); dist.OwnedBy != "" || len(ownershipIssues(target, ownershipAmbiguous)) != 1 {
			t.Fatalf("absolute and relative conflicting claims = %+v", target)
		}
	})
}

func TestOwnershipContractAbsentClaimsAreNotOwners(t *testing.T) {
	prefix := ownershipFixture(t)
	writeMeta(t, prefix, "ghost.json", hostRecordJSON("ghost", ownershipFiles("lib/python3.12/site-packages/missing-1.dist-info/METADATA")))
	target := ownershipCollect(t, prefix, 2)
	if dist := ownershipOnlyDist(t, target); dist.OwnedBy != "" || target.Coverage[CapPythonDistributions] != Complete || len(target.Issues) != 0 {
		t.Fatalf("unindexed claim produced ownership = %+v", target)
	}
}

func TestOwnershipContractUnknownOwnershipDoesNotDuplicate(t *testing.T) {
	prefix := ownershipFixture(t)
	// The default known-empty pkg.json from hostPrefix must not contribute a second issue.
	writeMeta(t, prefix, "unknown.json", strings.Replace(hostRecordJSON("unknown", ""), `,"files":[]`, "", 1))
	target := ownershipCollect(t, prefix, 2)
	issues := ownershipIssues(target, ownershipUnavailable)
	if len(issues) != 1 || issues[0].Path != filepath.Join(prefix, "conda-meta", "unknown.json") || target.Coverage[CapPythonDistributions] != Partial {
		t.Fatalf("unknown ownership issues = %+v, target %+v", issues, target)
	}
	if dist := ownershipOnlyDist(t, target); dist.OwnedBy != "" {
		t.Fatalf("unknown ownership assigned owner: %+v", dist)
	}
}

func TestOwnershipContractEmptyOwnerFirstIsNotAmbiguous(t *testing.T) {
	prefix := ownershipFixture(t)
	target := ownershipCollectSynthetic(t, prefix,
		ownershipSynthetic("", true, ownershipMetadata),
		ownershipSynthetic("owner", true, ownershipMetadata))
	if dist := ownershipOnlyDist(t, target); dist.OwnedBy != "owner" || len(target.Issues) != 0 || target.Coverage[CapPythonDistributions] != Complete {
		t.Fatalf("empty-first owner quirk = %+v, target %+v", dist, target)
	}
}

func TestOwnershipContractEmptyOwnerLastIsAmbiguous(t *testing.T) {
	prefix := ownershipFixture(t)
	target := ownershipCollectSynthetic(t, prefix,
		ownershipSynthetic("owner", true, ownershipMetadata),
		ownershipSynthetic("", true, ownershipMetadata))
	if dist := ownershipOnlyDist(t, target); dist.OwnedBy != "" || len(ownershipIssues(target, ownershipAmbiguous)) != 1 || target.Coverage[CapPythonDistributions] != Partial {
		t.Fatalf("empty-last owner quirk = %+v, target %+v", dist, target)
	}
}

func TestOwnershipContractKnownFalseWithClaimsIsPartial(t *testing.T) {
	prefix := ownershipFixture(t)
	record := ownershipSynthetic("partial", false, ownershipMetadata)
	target := ownershipCollectSynthetic(t, prefix, record)
	issues := ownershipIssues(target, ownershipUnavailable)
	if dist := ownershipOnlyDist(t, target); dist.OwnedBy != "partial" || target.Coverage[CapPythonDistributions] != Partial || len(issues) != 1 || issues[0].Path != record.Path {
		t.Fatalf("unknown ownership with claims = %+v, issues %+v", dist, issues)
	}
}
