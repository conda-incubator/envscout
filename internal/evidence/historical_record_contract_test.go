package evidence

import (
	"strings"
	"testing"

	"github.com/conda-incubator/envscout/internal/testimage"
)

// Historical conda-meta records feed layers.go through ParsePrefixRecord-equivalent
// canonical parsing. These literal contracts pin the observable outcomes so a
// parser migration cannot silently reject records the baseline accepts.

const historicalRecordFn = "conda-1.0-0.conda"

func historicalRecord(name, extra string) string {
	return `{"name":"` + name + `","version":"1.0","build":"0","build_number":0,"subdir":"linux-64","fn":"` + historicalRecordFn + `","url":"https://example.com/linux-64/` + historicalRecordFn + `"` + extra + `}`
}

func historicalEntry(p, data string) testimage.Entry {
	return testimage.Entry{Name: p, Data: data}
}

// historicalLayerTarget collects layer-retention for a two-layer image: the
// record/marker lives in the first layer and the archive is retained by the
// historical cache context.
func historicalLayerTarget(t *testing.T, record testimage.Entry, archive string) Target {
	t.Helper()
	loaded := loadEvidenceImage(t, []testimage.Entry{record, {Name: archive, Data: "archive"}}, []testimage.Entry{{Name: archive[:strings.LastIndex(archive, "/")] + "/.wh." + archive[strings.LastIndex(archive, "/")+1:]}})
	return collectFixture(t, loaded, CapLayerRetention, CapToolingPrefix, CapFinalCache)
}

func TestHistoricalRecordContractToolingRecordAccepted(t *testing.T) {
	// Canonical tooling record in conda-meta retains its pkgs cache context,
	// so the removed archive is retained and layer-retention stays complete.
	target := historicalLayerTarget(t, historicalEntry("opt/conda/conda-meta/conda.json", historicalRecord("conda", "")), "opt/conda/pkgs/pkg-1.0-0.conda")
	if target.Coverage[CapLayerRetention] != Complete || len(target.Retained) != 1 {
		t.Fatalf("tooling record not accepted: coverage=%v retained=%+v issues=%+v", target.Coverage, target.Retained, target.Issues)
	}
	if len(target.Issues) != 0 {
		t.Fatalf("unexpected issues for valid tooling record: %+v", target.Issues)
	}
}

func TestHistoricalRecordContractNonToolingExcluded(t *testing.T) {
	// A non-tooling conda-meta record never establishes a historical cache root,
	// so no retained artifact is produced and no record diagnostic is raised.
	target := historicalLayerTarget(t, historicalEntry("opt/conda/conda-meta/python.json", historicalRecord("python", "")), "opt/conda/pkgs/pkg-1.0-0.conda")
	if len(target.Retained) != 0 || len(target.Issues) != 0 {
		t.Fatalf("non-tooling record leaked into historical evidence: retained=%+v issues=%+v", target.Retained, target.Issues)
	}
}

func TestHistoricalRecordContractInvalidDiagnostics(t *testing.T) {
	// Invalid documents produce the exact baseline diagnostic text, not a fatal error.
	cases := map[string]string{
		"not-json":        `{`,
		"empty-object":    `{}`,
		"files-null":      historicalRecord("conda", `,"files":null`),
		"paths-data-null": historicalRecord("conda", `,"paths_data":null`),
		"paths-null":      historicalRecord("conda", `,"paths_data":{"paths_version":1,"paths":null}`),
		"files-string":    historicalRecord("conda", `,"files":"bin/x"`),
		"files-bad-elem":  historicalRecord("conda", `,"files":[1]`),
		"missing-fn":      `{"name":"conda","version":"1.0","build":"0","build_number":0,"subdir":"linux-64"}`,
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			target := historicalLayerTarget(t, historicalEntry("opt/conda/conda-meta/conda.json", doc), "opt/conda/pkgs/pkg-1.0-0.conda")
			if target.Coverage[CapLayerRetention] != Partial {
				t.Fatalf("invalid record must be partial: coverage=%v issues=%+v", target.Coverage, target.Issues)
			}
			found := false
			for _, issue := range target.Issues {
				found = found || (issue.Capability == CapLayerRetention && issue.Message == "invalid historical conda marker")
			}
			if !found {
				t.Fatalf("missing exact diagnostic: %+v", target.Issues)
			}
		})
	}
}

func TestHistoricalRecordContractOwnershipOmissionAccepted(t *testing.T) {
	// Omitted, explicit-empty, and uppercase-unknown ownership keys remain valid
	// for historical tooling: canonical parsing accepts them without rejection.
	for name, extra := range map[string]string{
		"omitted":         "",
		"files-empty":     `,"files":[]`,
		"paths-empty":     `,"paths_data":{"paths_version":1,"paths":[]}`,
		"uppercase-FILES": `,"FILES":[]`,
		"paths-data-omit": `,"paths_data":{"paths_version":1}`,
	} {
		t.Run(name, func(t *testing.T) {
			target := historicalLayerTarget(t, historicalEntry("opt/conda/conda-meta/conda.json", historicalRecord("conda", extra)), "opt/conda/pkgs/pkg-1.0-0.conda")
			if target.Coverage[CapLayerRetention] != Complete || len(target.Retained) != 1 || len(target.Issues) != 0 {
				t.Fatalf("accepted ownership state rejected: coverage=%v retained=%+v issues=%+v", target.Coverage, target.Retained, target.Issues)
			}
		})
	}
}

func TestHistoricalRecordContractEarlierPositiveSurvivesLaterInvalid(t *testing.T) {
	// A valid tooling record and a later invalid record in the same image: the
	// positive retained artifact survives, coverage is partial, and the invalid
	// record contributes exactly one diagnostic.
	loaded := loadEvidenceImage(t, []testimage.Entry{
		historicalEntry("opt/conda/conda-meta/conda.json", historicalRecord("conda", "")),
		{Name: "opt/conda/pkgs/pkg-1.0-0.conda", Data: "archive"},
		historicalEntry("opt/conda/conda-meta/broken.json", `{`),
	}, []testimage.Entry{{Name: "opt/conda/pkgs/.wh.pkg-1.0-0.conda"}})
	target := collectFixture(t, loaded, CapLayerRetention)
	if len(target.Retained) != 1 || target.Retained[0].Path != "/opt/conda/pkgs/pkg-1.0-0.conda" || target.Coverage[CapLayerRetention] != Partial {
		t.Fatalf("positive lost after later invalid: retained=%+v coverage=%v issues=%+v", target.Retained, target.Coverage, target.Issues)
	}
	historical := 0
	for _, issue := range target.Issues {
		if issue.Capability == CapLayerRetention && issue.Path == "/opt/conda/conda-meta/broken.json" && issue.Message == "invalid historical conda marker" {
			historical++
		}
	}
	if historical != 1 {
		t.Fatalf("historical diagnostic count=%d issues=%+v", historical, target.Issues)
	}
}

func TestHistoricalRecordContractToolingNameControlsRoot(t *testing.T) {
	// The inferred pkgs root derives from the conda-meta location and the tooling
	// name. A non-tooling name at the same location establishes no root.
	for name, want := range map[string]int{"conda": 1, "mamba": 1, "micromamba": 1, "python": 0} {
		t.Run(name, func(t *testing.T) {
			target := historicalLayerTarget(t, historicalEntry("opt/conda/conda-meta/"+name+".json", historicalRecord(name, "")), "opt/conda/pkgs/pkg-1.0-0.conda")
			if len(target.Retained) != want {
				t.Fatalf("name %s retained=%d want %d issues=%+v", name, len(target.Retained), want, target.Issues)
			}
		})
	}
}

func TestHistoricalRecordContractMarkerAndRecordReadBounds(t *testing.T) {
	// Oversize historical metadata is bounded by imageMetadataLimit and reported
	// as an unreadable-cache issue rather than being parsed or admitted.
	loaded := loadEvidenceImage(t, []testimage.Entry{historicalEntry("opt/conda/conda-meta/conda.json", historicalRecord("conda", "")), historicalEntry("opt/conda/conda-meta/big.json", strings.Repeat("x", imageMetadataLimit+1))})
	target := collectFixture(t, loaded, CapLayerRetention)
	if target.Coverage[CapLayerRetention] != Partial {
		t.Fatalf("oversize record not partial: %+v", target)
	}
}
