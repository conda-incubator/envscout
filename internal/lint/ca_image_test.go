package lint

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/conda-incubator/envscout/internal/evidence"
	"github.com/conda-incubator/envscout/internal/imageinput"
	"github.com/conda-incubator/envscout/internal/testimage"
)

func caImageRecord(name, version string) string {
	return fmt.Sprintf(`{"name":%q,"version":%q,"build":"0","build_number":0,"subdir":"noarch","channel":"conda-forge","fn":%q,"url":%q}`, name, version, name+"-"+version+"-0.conda", "https://conda.anaconda.org/conda-forge/noarch/"+name+"-"+version+"-0.conda")
}

func TestCAPackagesReadOnlyFinalImageMetadata(t *testing.T) {
	for _, version := range []string{"2026.7.22", "2026.10.19"} {
		t.Run(version, func(t *testing.T) {
			archive := testimage.Archive(t, []testimage.Entry{
				{Name: "opt/conda/conda-meta/certifi.json", Data: caImageRecord("certifi", "2026.7.22")},
				{Name: "opt/conda/conda-meta/history", Data: "invalid unrequested history"},
				{Name: "opt/conda/ssl/cacert.pem", Data: "not a valid PEM; content must not be inspected"},
			}, []testimage.Entry{
				{Name: "opt/conda/conda-meta/certifi.json", Data: caImageRecord("certifi", version)},
			})
			loaded, err := imageinput.Load(context.Background(), archive, "linux/amd64")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := loaded.Close(); err != nil {
					t.Error(err)
				}
			})
			policy, err := BuildPolicy(Policy{Version: ConfigVersion}, Options{Source: "oci-archive", Rules: []string{"ENV013"}})
			if err != nil {
				t.Fatal(err)
			}
			target, err := evidence.CollectImage(context.Background(), loaded, Requirements(policy))
			if err != nil || len(target.Issues) != 0 {
				t.Fatalf("metadata-only collection: %+v %v", target, err)
			}
			report := evaluateCAPackages(t, target)
			if version == "2026.10.19" {
				if len(report.Findings) != 0 || caReportStatus(t, report) != Pass {
					t.Fatalf("historical old metadata must not create a runtime finding: %+v", report)
				}
			} else if len(report.Findings) != 1 || !strings.Contains(report.Findings[0].Next, "image build") || report.Findings[0].Evidence.Paths[0] != "/opt/conda/conda-meta/certifi.json" {
				t.Fatalf("final image needs a source-qualified finding: %+v", report)
			}
			for capability, coverage := range target.Coverage {
				if capability != "prefixes" && capability != "conda-records" && coverage != evidence.NotCollected {
					t.Errorf("unrelated image capability collected: %s=%s", capability, coverage)
				}
			}
		})
	}
}
