package lint

import (
	"fmt"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/conda-incubator/envscout/internal/discovery"
	"github.com/conda-incubator/envscout/internal/evidence"
)

func evaluateCAPackages(t *testing.T, target evidence.Target) Report {
	t.Helper()
	policy, err := BuildPolicy(Policy{Version: ConfigVersion}, Options{Source: target.Kind, Rules: []string{"ENV013"}})
	if err != nil {
		t.Fatal(err)
	}
	return Evaluate(evidence.Snapshot{Targets: []evidence.Target{target}}, policy, time.Date(2026, 10, 26, 0, 0, 0, 0, time.UTC))
}

func caReportStatus(t *testing.T, report Report) Status {
	t.Helper()
	if len(report.Outcomes) == 1 {
		return report.Outcomes[0].Status
	}
	if report.OutcomeCounts[NotApplicable] == 1 {
		return NotApplicable
	}
	t.Fatalf("expected one active or inapplicable CA check: %+v", report)
	return ""
}

func TestCAPackageRemediationBoundaries(t *testing.T) {
	for _, test := range []struct {
		name, pkg, version, channel, minimum string
		status                               Status
	}{
		{"old forge certifi", "certifi", "2026.7.22", "conda-forge", "2026.10.19", FindingStatus},
		{"recommended forge certifi", "certifi", "2026.10.19", "conda-forge", "", Pass},
		{"latest forge certifi", "certifi", "2026.10.23", "conda-forge", "", Pass},
		{"fixed but below recommended", "certifi", "2026.10.18", "conda-forge", "2026.10.19", FindingStatus},
		{"old main certifi", "certifi", "2026.7.22", "https://repo.anaconda.com/pkgs/main/linux-64", "2026.10.19", FindingStatus},
		{"recommended main certifi", "certifi", "2026.10.19", "https://repo.anaconda.com/pkgs/main", "", Pass},
		{"old forge CA", "ca-certificates", "2026.7.22", "https://conda.anaconda.org/conda-forge/linux-64", "2026.10.19", FindingStatus},
		{"recommended forge CA", "ca-certificates", "2026.10.19", "conda-forge", "", Pass},
		{"latest forge CA", "ca-certificates", "2026.10.23", "conda-forge", "", Pass},
		{"old main CA", "ca-certificates", "2026.9.25", "https://repo.anaconda.com/pkgs/main", "2026.10.20", FindingStatus},
		{"main CA does not accept forge boundary", "ca-certificates", "2026.10.19", "https://repo.anaconda.com/pkgs/main", "2026.10.20", FindingStatus},
		{"recommended main CA", "ca-certificates", "2026.10.20", "https://repo.anaconda.com/pkgs/main", "", Pass},
		{"case-insensitive official host", "ca-certificates", "2026.10.19", "https://REPO.ANACONDA.COM/pkgs/main", "2026.10.20", FindingStatus},
		{"later conda rebuild version", "certifi", "2026.10.19.post1", "conda-forge", "", Pass},
		{"prerelease below minimum", "certifi", "2026.10.19rc1", "conda-forge", "2026.10.19", FindingStatus},
		{"unrelated package", "python", "3.13", "conda-forge", "", NotApplicable},
		{"custom channel", "certifi", "2026.7.22", "https://example.test/conda-forge", "", Unknown},
		{"missing channel", "certifi", "2026.7.22", "", "", Unknown},
		{"main lookalike", "certifi", "2026.7.22", "https://repo.anaconda.com/pkgs/main-extra", "", Unknown},
		{"forge lookalike", "certifi", "2026.7.22", "https://conda.anaconda.org/conda-forge-extra", "", Unknown},
		{"unresolved defaults multichannel", "certifi", "2026.7.22", "defaults", "", Unknown},
		{"invalid version", "certifi", "", "conda-forge", "", Unknown},
	} {
		t.Run(test.name, func(t *testing.T) {
			record := localRecord(test.pkg, test.version)
			record.Record.Channel = test.channel
			target := localTarget(record)
			report := evaluateCAPackages(t, target)
			if caReportStatus(t, report) != test.status {
				t.Fatalf("wrong CA outcome: %+v", report)
			}
			if test.status != FindingStatus {
				if len(report.Findings) != 0 {
					t.Fatalf("unexpected CA finding: %+v", report.Findings)
				}
				return
			}
			if len(report.Findings) != 1 || report.Findings[0].Severity != Warning || report.ExitCode() != 1 {
				t.Fatalf("expected one warning: %+v", report)
			}
			finding := report.Findings[0]
			for _, detail := range []string{test.pkg, test.version, test.minimum, "/env", record.Path, "October 2026"} {
				if !strings.Contains(finding.Message, detail) {
					t.Errorf("CA finding lacks %q: %s", detail, finding.Message)
				}
			}
			if strings.Contains(finding.Message, "vulnerable") || strings.Contains(finding.Message, "trusts") {
				t.Fatalf("metadata-only finding overclaims security: %s", finding.Message)
			}
			if test.version == "2026.10.18" && !strings.Contains(finding.Message, "already contains the upstream security fix") {
				t.Fatal("the first fixed certifi release must not be described as unpatched")
			}
		})
	}
}

func TestCAPackageRequirementsAndProfiles(t *testing.T) {
	for _, profile := range profiles {
		source := "oci-archive"
		if profile == "local" {
			source = "dir"
		}
		policy, err := BuildPolicy(Policy{Version: ConfigVersion}, Options{Source: source, Profile: profile, Rules: []string{"ENV013"}})
		if err != nil {
			t.Fatal(err)
		}
		if caps := Requirements(policy).Capabilities; !slices.Equal(caps, []string{"conda-records", "prefixes"}) {
			t.Fatalf("CA rule must use only existing package metadata: %v", caps)
		}
		want := []string(nil)
		if source == "dir" {
			want = []string{"prefixes", "python-distributions"}
		}
		if caps := Requirements(policy).VirtualenvCapabilities; !slices.Equal(caps, want) {
			t.Fatalf("virtualenv evidence is local-only: %v, want %v", caps, want)
		}
		rule, _ := LookupRule("ENV013")
		if !rule.Defaults[profile].Enabled || rule.Defaults[profile].Severity != Warning {
			t.Fatalf("CA rule must default to warning for %s", profile)
		}
	}
}

func TestCAPackagePartialEvidenceKeepsKnownFindings(t *testing.T) {
	target := localTarget(localRecord("certifi", "2026.7.22"))
	target.Coverage["conda-records"] = evidence.Partial
	target.Prefixes[0].RecordCoverage = evidence.Partial
	report := evaluateCAPackages(t, target)
	if len(report.Findings) != 1 || report.Status != "incomplete" || report.ExitCode() != 2 {
		t.Fatalf("partial metadata must preserve proven positives without claiming completeness: %+v", report)
	}
	target.Prefixes[0].Records[0].Record.Version = "2026.10.19"
	report = evaluateCAPackages(t, target)
	if len(report.Findings) != 0 || report.Outcomes[0].Status != Unknown {
		t.Fatalf("partial metadata cannot establish a pass: %+v", report)
	}
}

func TestCAPackageMissingScopeAndRecordPath(t *testing.T) {
	target := localTarget()
	target.Prefixes = nil
	if report := evaluateCAPackages(t, target); caReportStatus(t, report) != NotApplicable {
		t.Fatalf("no environment is not applicable: %+v", report)
	}
	target = localTarget(localRecord("certifi", "2026.7.22"))
	target.Prefixes[0].Records[0].Path = ""
	if report := evaluateCAPackages(t, target); report.Outcomes[0].Status != Unknown || len(report.Findings) != 0 {
		t.Fatalf("a package observation needs a source path: %+v", report)
	}
}

func TestCAPackageKnownPositiveSurvivesUnknownChannel(t *testing.T) {
	known := localRecord("certifi", "2026.7.22")
	known.Record.Channel = "https://secret:password@conda.anaconda.org/conda-forge/linux-64"
	unknown := localRecord("ca-certificates", "2026.7.22")
	unknown.Record.Channel = "https://example.test/private"
	target := localTarget(known, unknown)
	report := evaluateCAPackages(t, target)
	if len(report.Findings) != 1 || !strings.Contains(report.Outcomes[0].Reason, "unknown") {
		t.Fatalf("a known old package must survive unsupported channel evidence: %+v", report)
	}
	for _, finding := range report.Findings {
		if strings.Contains(finding.Message+finding.Next, "secret") || strings.Contains(finding.Message+finding.Next, "password") {
			t.Fatal("CA finding must not expose channel credentials")
		}
	}
	if target.Prefixes[0].Records[0].Record.Channel != known.Record.Channel {
		t.Fatal("CA checks must not mutate canonical records")
	}
}

func TestCAPackageEvaluationStopsAtFindingLimit(t *testing.T) {
	target := localTarget()
	for i := range MaxFindings + 1 {
		record := localRecord("certifi", "2026.7.22")
		record.Path = fmt.Sprintf("/env/conda-meta/certifi-%d.json", i)
		target.Prefixes[0].Records = append(target.Prefixes[0].Records, record)
	}
	report := evaluateCAPackages(t, target)
	if len(report.Findings) != MaxFindings || report.Status != "incomplete" || report.ExitCode() != 2 {
		t.Fatalf("limited CA evaluation cannot claim completion: %d findings, status=%s", len(report.Findings), report.Status)
	}
	if !slices.ContainsFunc(report.Issues, func(issue evidence.Issue) bool {
		return issue.Capability == "evaluation" && strings.Contains(issue.Message, "limit")
	}) {
		t.Fatal("finding limit must be explained as an evaluation issue")
	}
}

func TestCAPackageUpdateActionAndImageScope(t *testing.T) {
	target := localTarget(localRecord("certifi", "2026.7.22"), localRecord("ca-certificates", "2026.7.22"))
	target.Prefixes[0].Path = "/env with ' quote"
	report := evaluateCAPackages(t, target)
	if len(report.Findings) != 2 {
		t.Fatalf("both outdated packages should be reported: %+v", report)
	}
	if runtime.GOOS != "windows" {
		for _, finding := range report.Findings {
			if !strings.Contains(finding.Next, "--prefix "+commandArg(target.Prefixes[0].Path)) || !strings.Contains(finding.Next, "conda install") {
				t.Errorf("update must identify the prefix safely: %s", finding.Next)
			}
			if strings.Contains(finding.Next, "--override-channels") || !strings.Contains(finding.Next, "https://conda.anaconda.org/conda-forge::") {
				t.Errorf("target only the CA package's official channel, preserving configured dependency channels: %s", finding.Next)
			}
		}
	}
	target.Kind = "oci-archive"
	report = evaluateCAPackages(t, target)
	for _, finding := range report.Findings {
		if !strings.Contains(finding.Next, "image build") || strings.Contains(finding.Next, "--prefix '/env") {
			t.Errorf("image update must not target a host prefix: %s", finding.Next)
		}
	}
}

func TestVirtualenvCertifiEvidenceBoundaries(t *testing.T) {
	for _, test := range []struct {
		name, version, path, coverage string
		status                        Status
		findings                      int
	}{
		{"old", "2026.7.22", "/venv/Lib/site-packages/certifi.dist-info/METADATA", evidence.Complete, FindingStatus, 1},
		{"fixed", "2026.10.18", "/venv/Lib/site-packages/certifi.dist-info/METADATA", evidence.Complete, Pass, 0},
		{"prerelease", "2026.10.18rc1", "/venv/Lib/site-packages/certifi.dist-info/METADATA", evidence.Complete, FindingStatus, 1},
		{"invalid", "invalid", "/venv/Lib/site-packages/certifi.dist-info/METADATA", evidence.Complete, Unknown, 0},
		{"no path", "2026.7.22", "", evidence.Complete, Unknown, 0},
		{"outside", "2026.7.22", "/outside/certifi.dist-info/METADATA", evidence.Complete, Unknown, 0},
		{"partial positive", "2026.7.22", "/venv/Lib/site-packages/certifi.dist-info/METADATA", evidence.Partial, FindingStatus, 1},
		{"partial fixed", "2026.10.18", "/venv/Lib/site-packages/certifi.dist-info/METADATA", evidence.Partial, Unknown, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			target := evidence.Target{ID: "venv", Kind: "dir", Input: "/venv", Prefixes: []evidence.Prefix{{Kind: discovery.KindVenv, Path: "/venv"}},
				Python:   []evidence.PythonDistribution{{Name: "certifi", Version: test.version, Path: test.path}},
				Coverage: map[string]string{"prefixes": evidence.Complete, "python-distributions": test.coverage}}
			report := evaluateCAPackages(t, target)
			if caReportStatus(t, report) != test.status || len(report.Findings) != test.findings {
				t.Fatalf("virtualenv certifi evidence: %+v", report)
			}
			if (report.Status == "incomplete") != (test.coverage != evidence.Complete) {
				t.Fatalf("coverage must not claim completion: %+v", report)
			}
		})
	}
}

func TestVirtualenvRuleSupportIsExplicit(t *testing.T) {
	target := evidence.Target{ID: "venv", Kind: "dir", Input: "/venv", Prefixes: []evidence.Prefix{{Kind: discovery.KindVenv, Path: "/venv"}},
		Python:   []evidence.PythonDistribution{{Name: "certifi", Version: "2026.7.22", Path: "/venv/Lib/site-packages/certifi.dist-info/METADATA"}},
		Coverage: map[string]string{"prefixes": evidence.Complete, "python-distributions": evidence.Complete}}
	p := enginePolicy(t, "dir", "local", "ENV003", "ENV013")
	report := engineEvaluate(target, p)
	if report.Status != "incomplete" || engineOutcome(t, report, "ENV003").Status != Unknown || engineOutcome(t, report, "ENV013").Status != FindingStatus || len(report.Findings) != 1 || report.Findings[0].RuleID != "ENV013" {
		t.Fatalf("unsupported conda rules must not classify virtualenv distributions: %+v", report)
	}
	rule, _ := LookupRule("ENV013")
	rule.VirtualenvCapabilities[0] = "mutated"
	if next, _ := LookupRule("ENV013"); next.VirtualenvCapabilities[0] == "mutated" {
		t.Fatal("virtualenv requirements must not expose registry mutation")
	}
}
