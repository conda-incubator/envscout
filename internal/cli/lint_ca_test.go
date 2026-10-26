package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	policy "github.com/conda-incubator/envscout/internal/lint"
)

// caRecord returns a canonical conda-meta document for a certificate package.
// Only package metadata is written; no certificate bundle content is created.
func caRecord(name, version, channel, url string) string {
	return fmt.Sprintf(`{"name":%q,"version":%q,"build":"0","build_number":0,"subdir":"noarch","channel":%q,"files":[],"fn":%q,"url":%q}`,
		name, version, channel, name+"-"+version+"-0.conda", url)
}

// caPrefix writes a conda prefix whose only metadata is the given certificate
// records. It deliberately writes no Python distributions, cache, or bundle files.
func caPrefix(t *testing.T, records map[string]string) string {
	t.Helper()
	prefix := filepath.Join(t.TempDir(), "env")
	meta := filepath.Join(prefix, "conda-meta")
	if err := os.MkdirAll(meta, 0o755); err != nil {
		t.Fatal(err)
	}
	for file, data := range records {
		if err := os.WriteFile(filepath.Join(meta, file), []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return prefix
}

const (
	mainChannel  = "https://repo.anaconda.com/pkgs/main"
	forgeChannel = "https://conda.anaconda.org/conda-forge"
)

// caStaleFixture: ca-certificates from the official main channel at 2026.10.19,
// below its 2026.10.20 minimum, next to certifi at its main minimum 2026.10.19
// (not stale). Exactly one ENV013 finding is expected.
func caStaleFixture(t *testing.T) string {
	return caPrefix(t, map[string]string{
		"certifi-2026.10.19-0.json":         caRecord("certifi", "2026.10.19", mainChannel, mainChannel+"/noarch/certifi-2026.10.19-0.conda"),
		"ca-certificates-2026.10.19-0.json": caRecord("ca-certificates", "2026.10.19", mainChannel, mainChannel+"/noarch/ca-certificates-2026.10.19-0.conda"),
	})
}

// caFixedFixture: certifi and ca-certificates at or above the conda-forge minima.
func caFixedFixture(t *testing.T) string {
	return caPrefix(t, map[string]string{
		"certifi-2026.10.23-0.json":         caRecord("certifi", "2026.10.23", forgeChannel, forgeChannel+"/noarch/certifi-2026.10.23-0.conda"),
		"ca-certificates-2026.10.19-0.json": caRecord("ca-certificates", "2026.10.19", forgeChannel, forgeChannel+"/noarch/ca-certificates-2026.10.19-0.conda"),
	})
}

// lintENV013JSON runs `lint --rule ENV013 --format json` and decodes the
// ENV013 findings and outcome for the given prefix.
func lintENV013JSON(t *testing.T, prefix string) (findings []map[string]any, status string) {
	t.Helper()
	output, err := executeLint(t, "--rule", "ENV013", "--format", "json", "--fail-on", "none", prefix)
	if err != nil {
		t.Fatalf("lint ENV013: %v %s", err, output)
	}
	var report struct {
		Findings []map[string]any `json:"findings"`
		Outcomes []struct {
			RuleID string `json:"rule_id"`
			Status string `json:"status"`
		} `json:"outcomes"`
		OutcomeCounts map[string]int `json:"outcome_counts"`
	}
	if err := json.Unmarshal([]byte(output), &report); err != nil {
		t.Fatalf("decode: %v: %s", err, output)
	}
	// Outcomes omit not-applicable checks; read ENV013 from outcomes when present,
	// otherwise derive the single status from the outcome counts for this run.
	for _, o := range report.Outcomes {
		if o.RuleID == "ENV013" {
			status = o.Status
		}
	}
	if status == "" && report.OutcomeCounts[string(policy.NotApplicable)] > 0 {
		status = string(policy.NotApplicable)
	}
	for _, f := range report.Findings {
		if f["rule_id"] == "ENV013" {
			findings = append(findings, f)
		}
	}
	return findings, status
}

// TestLintENV013MixedFixedAndStalePackagesReportOnlyStale covers one prefix
// with a fixed certifi and a stale ca-certificates: exactly one finding.
func TestLintENV013MixedFixedAndStalePackagesReportOnlyStale(t *testing.T) {
	t.Chdir(t.TempDir())
	findings, status := lintENV013JSON(t, caStaleFixture(t))
	if status != string(policy.FindingStatus) {
		t.Fatalf("status = %q, want %q", status, policy.FindingStatus)
	}
	if len(findings) != 1 || !strings.Contains(fmt.Sprint(findings[0]["message"]), "ca-certificates") {
		t.Fatalf("findings = %d, want one ca-certificates finding: %+v", len(findings), findings)
	}
	for _, f := range findings {
		if f["severity"] != "warning" {
			t.Errorf("severity = %v, want warning (default across profiles): %+v", f["severity"], f)
		}
		message, _ := f["message"].(string)
		if !strings.Contains(message, "certifi") && !strings.Contains(message, "ca-certificates") {
			t.Errorf("finding does not name the package: %q", message)
		}
	}
	lower := strings.ToLower(fmt.Sprint(findings))
	for _, claim := range []string{"is vulnerable", "trusted at runtime", "runtime trust"} {
		if strings.Contains(lower, claim) {
			t.Errorf("finding claims %q: %s", claim, lower)
		}
	}
}

// TestLintENV013TwoOwnershipPathsReportTwoStalePackages covers two conda-meta
// ownership paths, each holding a stale certificate package: two findings with
// distinct metadata paths.
func TestLintENV013TwoOwnershipPathsReportTwoStalePackages(t *testing.T) {
	t.Chdir(t.TempDir())
	root := t.TempDir()
	mk := func(name string, records map[string]string) string {
		prefix := filepath.Join(root, name)
		meta := filepath.Join(prefix, "conda-meta")
		if err := os.MkdirAll(meta, 0o755); err != nil {
			t.Fatal(err)
		}
		for file, data := range records {
			if err := os.WriteFile(filepath.Join(meta, file), []byte(data), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		return prefix
	}
	first := mk("one", map[string]string{
		"ca-certificates-2026.10.19-0.json": caRecord("ca-certificates", "2026.10.19", mainChannel, mainChannel+"/noarch/ca-certificates-2026.10.19-0.conda"),
	})
	second := mk("two", map[string]string{
		"certifi-2026.7.22-0.json": caRecord("certifi", "2026.7.22", forgeChannel, forgeChannel+"/noarch/certifi-2026.7.22-0.conda"),
	})
	output, err := executeLint(t, "--rule", "ENV013", "--format", "json", "--fail-on", "none", first, second)
	if err != nil {
		t.Fatalf("lint: %v %s", err, output)
	}
	var report struct {
		Findings []struct {
			RuleID   string `json:"rule_id"`
			Evidence struct {
				Paths []string `json:"paths"`
			} `json:"evidence"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(output), &report); err != nil {
		t.Fatalf("decode: %v", err)
	}
	seen := map[string]bool{}
	for _, f := range report.Findings {
		if f.RuleID != "ENV013" || len(f.Evidence.Paths) == 0 {
			continue
		}
		seen[f.Evidence.Paths[0]] = true
	}
	if len(seen) != 2 {
		t.Fatalf("want two distinct ENV013 metadata paths, got %v", seen)
	}
}

func TestLintENV013FixedPackagesPass(t *testing.T) {
	t.Chdir(t.TempDir())
	findings, status := lintENV013JSON(t, caFixedFixture(t))
	if status != string(policy.Pass) || len(findings) != 0 {
		t.Fatalf("fixed certificates: status=%q findings=%+v", status, findings)
	}
}

func TestLintENV013PackagesOnlyNoPythonOrCacheContent(t *testing.T) {
	t.Chdir(t.TempDir())
	prefix := caStaleFixture(t)
	// Certificate bundle and Python content must never be read or reported.
	if err := os.MkdirAll(filepath.Join(prefix, "ssl"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(prefix, "ssl", "cacert.pem"), []byte("-----BEGIN CERTIFICATE-----\nMII\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	findings, _ := lintENV013JSON(t, prefix)
	for _, f := range findings {
		body, _ := json.Marshal(f)
		if strings.Contains(string(body), "cacert.pem") || strings.Contains(string(body), "BEGIN CERTIFICATE") {
			t.Fatalf("finding exposes certificate content: %s", body)
		}
	}
}

func TestLintENV013JSONPathActionAndRequirementsDomain(t *testing.T) {
	t.Chdir(t.TempDir())
	findings, _ := lintENV013JSON(t, caStaleFixture(t))
	if len(findings) == 0 {
		t.Fatal("expected findings")
	}
	for _, f := range findings {
		evidence, _ := f["evidence"].(map[string]any)
		paths, _ := evidence["paths"].([]any)
		if len(paths) == 0 || !strings.Contains(fmt.Sprint(paths[0]), "conda-meta") {
			t.Errorf("finding must carry metadata path: %+v", f)
		}
		if next, _ := f["next"].(string); next == "" {
			t.Errorf("finding must carry a next action: %+v", f)
		}
	}
}

func TestLintENV013UnknownForCustomOrMissingChannel(t *testing.T) {
	t.Chdir(t.TempDir())
	prefix := caPrefix(t, map[string]string{
		"certifi-2026.10.19-0.json": caRecord("certifi", "2026.10.19", "https://mirror.example.com/conda", "https://mirror.example.com/conda/noarch/certifi-2026.10.19-0.conda"),
	})
	findings, status := lintENV013JSON(t, prefix)
	if len(findings) != 0 || status != string(policy.Unknown) {
		t.Fatalf("custom channel: status=%q findings=%+v, want unknown with no findings", status, findings)
	}
}

func TestLintENV013NotApplicableWithoutCertificatePackages(t *testing.T) {
	t.Chdir(t.TempDir())
	prefix := caPrefix(t, map[string]string{
		"demo-1.0-0.json": caRecord("demo", "1.0", mainChannel, mainChannel+"/noarch/demo-1.0-0.conda"),
	})
	findings, status := lintENV013JSON(t, prefix)
	if len(findings) != 0 || status != string(policy.NotApplicable) {
		t.Fatalf("no selected certificate packages: status=%q findings=%+v, want not_applicable", status, findings)
	}
}

func TestLintENV013LegacyCertifiBelowMinimumRemainsWarning(t *testing.T) {
	t.Chdir(t.TempDir())
	// certifi 2026.10.18 is below the conda-forge minimum 2026.10.23. The
	// upstream fix for the earlier certifi.18 advisory is already present, so the
	// finding is remediation guidance, not a vulnerability claim.
	prefix := caPrefix(t, map[string]string{
		"certifi-2026.10.18-0.json": caRecord("certifi", "2026.10.18", forgeChannel, forgeChannel+"/noarch/certifi-2026.10.18-0.conda"),
	})
	findings, _ := lintENV013JSON(t, prefix)
	if len(findings) != 1 {
		t.Fatalf("findings = %+v", findings)
	}
	if findings[0]["severity"] != "warning" {
		t.Errorf("severity = %v, want warning", findings[0]["severity"])
	}
	// The remediation wording must not present the stale release as an active vulnerability.
	if strings.Contains(strings.ToLower(fmt.Sprint(findings[0])), "is vulnerable") {
		t.Errorf("minimum-version finding claims vulnerability: %+v", findings[0])
	}
}
