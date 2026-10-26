package lint

import (
	"encoding/json"
	"fmt"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/conda-incubator/envscout/internal/evidence"
	"github.com/conda-incubator/envscout/internal/inventory"
	gorattler "github.com/conda-incubator/go-rattler"
)

func localRecord(name, version string) inventory.CondaRecord {
	return inventory.CondaRecord{Path: "/env/conda-meta/" + name + ".json", OwnershipKnown: true, Record: gorattler.PrefixRecord{
		PackageRecord: gorattler.PackageRecord{Name: name, Version: version, Build: "build_0", Subdir: "linux-64", SHA256: strings.Repeat("a", 64)},
		Channel:       "conda-forge", Filename: name + "-" + version + "-build_0.conda",
		URL: "https://conda.anaconda.org/conda-forge/linux-64/" + name + "-" + version + "-build_0.conda",
	}}
}

func localTarget(records ...inventory.CondaRecord) evidence.Target {
	return evidence.Target{ID: "local", Kind: "dir", AsOf: time.Date(2026, 10, 26, 0, 0, 0, 0, time.UTC),
		Prefixes: []evidence.Prefix{{Path: "/env", Records: records, RecordCoverage: evidence.Complete}},
		Coverage: map[string]string{"prefixes": evidence.Complete, "conda-records": evidence.Complete,
			"python-distributions": evidence.Complete, "host-cache": evidence.Complete, "installed-lock": evidence.Complete}}
}

func localDistribution(name, version, owner string) evidence.PythonDistribution {
	return evidence.PythonDistribution{Name: name, Version: version, OwnedBy: owner,
		Path: "/env/lib/python3.14/site-packages/" + name + "-" + version + ".dist-info/METADATA"}
}

func TestUnownedDistributionSurvivesUnrelatedDiscoveryFailure(t *testing.T) {
	target := localTarget(localRecord("python", "3.13"))
	target.Python = []evidence.PythonDistribution{localDistribution("click", "8", "")}
	target.Coverage["prefixes"] = evidence.Partial
	outcome, findings := runLocalCheck(target, "ENV003", checkPipInstalled)
	if outcome.Status != FindingStatus || len(findings) != 1 || !strings.Contains(outcome.Reason, "incomplete") {
		t.Fatalf("known local ownership should survive unrelated discovery gaps: %+v %+v", outcome, findings)
	}
	target.Prefixes[0].RecordCoverage = evidence.Partial
	outcome, findings = runLocalCheck(target, "ENV003", checkPipInstalled)
	if outcome.Status != Unknown || len(findings) != 0 {
		t.Fatalf("unknown local ownership cannot establish absence: %+v %+v", outcome, findings)
	}
}

func TestUnownedDistributionCoverageIsPerPrefix(t *testing.T) {
	target := localTarget(localRecord("python", "3.13"))
	target.Python = []evidence.PythonDistribution{localDistribution("click", "8", "")}
	other := evidence.Prefix{Path: "/other", Records: []inventory.CondaRecord{localRecord("python", "3.13")}, RecordCoverage: evidence.Partial}
	target.Prefixes = append(target.Prefixes, other)
	target.Coverage["conda-records"] = evidence.Partial
	outcome, findings := runLocalCheck(target, "ENV003", checkPipInstalled)
	if outcome.Status != FindingStatus || len(findings) != 1 || !strings.Contains(outcome.Reason, "incomplete") {
		t.Fatalf("an unrelated incomplete prefix must not erase local ownership evidence: %+v %+v", outcome, findings)
	}
	// A nested incomplete prefix must not borrow its parent's complete ownership.
	target.Prefixes[1].Path = "/env/envs/other"
	target.Python[0].Path = "/env/envs/other/lib/python3.13/site-packages/click-8.dist-info/METADATA"
	outcome, findings = runLocalCheck(target, "ENV003", checkPipInstalled)
	if outcome.Status != Unknown || len(findings) != 0 {
		t.Fatalf("nested prefixes need their own complete ownership: %+v %+v", outcome, findings)
	}
}

func TestUnownedDistributionRequiresKnownRecordOwnership(t *testing.T) {
	target := localTarget(localRecord("python", "3.13"))
	target.Prefixes[0].Records[0].OwnershipKnown = false
	target.Python = []evidence.PythonDistribution{localDistribution("click", "8", "")}
	outcome, findings := runLocalCheck(target, "ENV003", checkPipInstalled)
	if outcome.Status != Unknown || len(findings) != 0 {
		t.Fatalf("coverage labels cannot substitute for omitted ownership fields: %+v %+v", outcome, findings)
	}
}

func TestOrphanConflictRequiresKnownRecordOwnership(t *testing.T) {
	target := localTarget(localRecord("numpy", "2"))
	target.Prefixes[0].Records[0].OwnershipKnown = false
	target.Python = []evidence.PythonDistribution{localDistribution("numpy", "2", "numpy"), localDistribution("numpy", "3", "")}
	outcome, findings := runLocalCheck(target, "ENV004", checkPipShadows)
	if outcome.Status != Unknown || len(findings) != 0 {
		t.Fatalf("orphan comparisons cannot assume omitted record ownership is complete: %+v %+v", outcome, findings)
	}
}

func TestPythonConflictDoesNotBorrowParentOwnership(t *testing.T) {
	target := localTarget(localRecord("numpy", "2"))
	child := evidence.Prefix{Path: "/env/envs/other", Records: []inventory.CondaRecord{localRecord("numpy", "3")}, RecordCoverage: evidence.Complete}
	target.Prefixes = append(target.Prefixes, child)
	distribution := localDistribution("numpy", "3", "numpy")
	distribution.Path = child.Path + "/lib/python3.13/site-packages/numpy-3.dist-info/METADATA"
	target.Python = []evidence.PythonDistribution{distribution}
	outcome, findings := runLocalCheck(target, "ENV004", checkPipShadows)
	if outcome.Status != Pass || len(findings) != 0 {
		t.Fatalf("a child environment must not compare against the parent's conda package: %+v %+v", outcome, findings)
	}
}

func TestRequestedSpecsReportAnyUnconstrainedRequest(t *testing.T) {
	record := localRecord("numpy", "2")
	record.Record.RequestedSpecs = []string{"numpy", "numpy >=1"}
	outcome, findings := runLocalCheck(localTarget(record), "ENV012", checkRequestedSpecs)
	if outcome.Status != FindingStatus || len(findings) != 1 || findings[0].Evidence.Count != 1 {
		t.Fatalf("a constrained request does not erase a separately unconstrained one: %+v %+v", outcome, findings)
	}
	record.Record.RequestedSpecs = []string{"numpy >=1", "numpy <2"}
	outcome, findings = runLocalCheck(localTarget(record), "ENV012", checkRequestedSpecs)
	if outcome.Status != Pass || len(findings) != 0 {
		t.Fatalf("requested-spec satisfaction is not part of the constraint-presence rule: %+v %+v", outcome, findings)
	}
}

func TestMixedChannelsIncludesWindowsDefaults(t *testing.T) {
	defaults := localRecord("m2-patch", "2.7.5")
	defaults.Record.Subdir = "win-64"
	defaults.Record.Channel = "https://repo.anaconda.com/pkgs/msys2/win-64"
	forge := localRecord("numpy", "2")
	forge.Record.Subdir = "win-64"
	target := localTarget(defaults, forge)
	outcome, findings := runLocalCheck(target, "ENV007", checkMixedChannels)
	if outcome.Status != FindingStatus || len(findings) != 1 {
		t.Fatalf("official msys2 defaults member must be classified: %+v %+v", outcome, findings)
	}
	target.Prefixes[0].Records[0].Record.Channel = "https://repo.anaconda.com/pkgs/msys2-lookalike/win-64"
	outcome, findings = runLocalCheck(target, "ENV007", checkMixedChannels)
	if outcome.Status != Pass || len(findings) != 0 {
		t.Fatalf("only the exact official defaults member counts: %+v %+v", outcome, findings)
	}
}

func TestPythonConflictEvaluationStopsBeforeCartesianExplosion(t *testing.T) {
	target := localTarget(localRecord("numpy", "2"))
	for i := range 100 {
		owned := localDistribution("numpy", "3", "numpy")
		owned.Path = fmt.Sprintf("/env/lib/python3.13/site-packages/owned-%d.dist-info/METADATA", i)
		orphan := localDistribution("numpy", "4", "")
		orphan.Path = fmt.Sprintf("/env/lib/python3.13/site-packages/orphan-%d.dist-info/METADATA", i)
		target.Python = append(target.Python, owned, orphan)
	}
	rule, _ := LookupRule("ENV004")
	outcome, findings := checkPipShadows(target, RuleOptions{Severity: Info}, rule)
	if len(findings) > MaxFindings || !strings.Contains(outcome.Reason, "limit") {
		t.Fatalf("conflict evaluation must stop before materializing every pair: %d findings, %+v", len(findings), outcome)
	}
	policy, err := BuildPolicy(Policy{Version: ConfigVersion}, Options{Source: "dir", Rules: []string{"ENV004"}})
	if err != nil {
		t.Fatal(err)
	}
	report := Evaluate(evidence.Snapshot{Targets: []evidence.Target{target}}, policy, target.AsOf)
	if report.Status != "incomplete" || len(report.Findings) > MaxFindings {
		t.Fatalf("a limited evaluation cannot claim completeness: %+v", report)
	}
}

func BenchmarkDuplicateEvaluationManyPrefixes(b *testing.B) {
	policy, err := BuildPolicy(Policy{Version: ConfigVersion}, Options{Source: "dir", Rules: []string{"ENV006"}})
	if err != nil {
		b.Fatal(err)
	}
	snapshot := evidence.Snapshot{}
	for i := range 30 {
		target := localTarget()
		target.ID = fmt.Sprintf("target-%d", i)
		target.Prefixes[0].Path = fmt.Sprintf("/env-%d", i)
		for j := range 100 {
			target.Prefixes[0].Records = append(target.Prefixes[0].Records, localRecord(fmt.Sprintf("package-%d", j), "1"))
		}
		snapshot.Targets = append(snapshot.Targets, target)
	}
	b.ResetTimer()
	for b.Loop() {
		report := Evaluate(snapshot, policy, time.Date(2026, 10, 26, 0, 0, 0, 0, time.UTC))
		if len(report.Findings) != len(snapshot.Targets) {
			b.Fatal("lost duplicate findings")
		}
	}
}

func TestStaticRuleLimitsLiveInCatalogueNotEveryFinding(t *testing.T) {
	target := localTarget(localRecord("python", "3.10.16"))
	target.Python = []evidence.PythonDistribution{localDistribution("click", "8", "")}
	for _, test := range []struct {
		id    string
		check func(evidence.Target, RuleOptions, Rule) (Outcome, []Finding)
	}{{"ENV003", checkPipInstalled}, {"ENV009", checkPythonEOL}} {
		_, findings := runLocalCheck(target, test.id, test.check)
		if len(findings) == 0 || len(findings[0].Evidence.Notes) != 0 {
			t.Fatalf("%s static limitations belong to --list-rules, not per-instance notes: %+v", test.id, findings)
		}
		rule, _ := LookupRule(test.id)
		if len(rule.Exceptions) == 0 {
			t.Fatalf("%s lost its documented limitations", test.id)
		}
	}
}

func runLocalCheck(target evidence.Target, id string, check func(evidence.Target, RuleOptions, Rule) (Outcome, []Finding)) (Outcome, []Finding) {
	rule := Rule{ID: id, Available: true, TargetKinds: []string{"dir"}, Check: check}
	if registered, ok := LookupRule(id); ok {
		rule = registered
	}
	enabled := true
	return evaluateRule(target, Policy{Rules: map[string]RuleOptions{id: {Enabled: &enabled, Severity: Warning}}}, rule)
}

func TestLocalRulesPositiveNegativeUnknown(t *testing.T) {
	tests := []struct {
		id                          string
		check                       func(evidence.Target, RuleOptions, Rule) (Outcome, []Finding)
		positive, negative, unknown func() evidence.Target
	}{
		{"ENV003", checkPipInstalled,
			func() evidence.Target {
				x := localTarget(localRecord("numpy", "2"))
				x.Python = []evidence.PythonDistribution{localDistribution("click", "8", "")}
				return x
			},
			func() evidence.Target {
				x := localTarget(localRecord("numpy", "2"))
				x.Python = []evidence.PythonDistribution{localDistribution("numpy", "2", "numpy")}
				return x
			},
			func() evidence.Target {
				x := localTarget(localRecord("numpy", "2"))
				x.Python = []evidence.PythonDistribution{localDistribution("click", "8", "")}
				x.Coverage["conda-records"] = evidence.Partial
				x.Prefixes[0].RecordCoverage = evidence.Partial
				return x
			}},
		{"ENV004", checkPipShadows,
			func() evidence.Target {
				x := localTarget(localRecord("numpy", "2"))
				x.Python = []evidence.PythonDistribution{localDistribution("numpy", "2", "numpy"), localDistribution("NumPy", "3", "")}
				return x
			},
			func() evidence.Target {
				x := localTarget(localRecord("numpy", "2"))
				x.Python = []evidence.PythonDistribution{localDistribution("numpy", "2", "numpy"), localDistribution("NUMPY", "2.0", "")}
				return x
			},
			func() evidence.Target {
				x := localTarget(localRecord("numpy", "2"))
				x.Python = []evidence.PythonDistribution{localDistribution("numpy", "not a version!", "numpy")}
				return x
			}},
		{"ENV005", checkWorkingBase,
			func() evidence.Target {
				c := localRecord("conda", "24")
				c.Record.Depends = []string{"python >=3.11"}
				return localTarget(c, localRecord("python", "3.14"), localRecord("numpy", "2"))
			},
			func() evidence.Target {
				c := localRecord("conda", "24")
				c.Record.Depends = []string{"python >=3.11"}
				return localTarget(c, localRecord("python", "3.14"))
			},
			func() evidence.Target {
				c := localRecord("conda", "24")
				c.Record.Depends = []string{"python >=3.11"}
				return localTarget(c, localRecord("numpy", "2"))
			}},
		{"ENV006", checkDuplicates,
			func() evidence.Target {
				x := localTarget(localRecord("numpy", "2"))
				peer := x.Prefixes[0]
				peer.Path = "/other"
				x.Peers = []evidence.Prefix{x.Prefixes[0], peer}
				return x
			},
			func() evidence.Target {
				x := localTarget(localRecord("numpy", "2"))
				peer := evidence.Prefix{Path: "/other", RecordCoverage: evidence.Complete, Records: []inventory.CondaRecord{localRecord("numpy", "3")}}
				x.Peers = []evidence.Prefix{x.Prefixes[0], peer}
				return x
			},
			func() evidence.Target {
				x := localTarget(localRecord("numpy", "2"))
				x.Prefixes[0].Records[0].Record.Channel = ""
				x.Peers = []evidence.Prefix{x.Prefixes[0]}
				return x
			}},
		{"ENV007", checkMixedChannels,
			func() evidence.Target {
				a := localRecord("python", "3.14")
				a.Record.Channel = "https://repo.anaconda.com/pkgs/main"
				return localTarget(a, localRecord("numpy", "2"))
			},
			func() evidence.Target { return localTarget(localRecord("python", "3.14"), localRecord("numpy", "2")) },
			func() evidence.Target {
				a := localRecord("python", "3.14")
				a.Record.Channel = "defaults"
				return localTarget(a, localRecord("numpy", "2"))
			}},
		{"ENV008", checkHostCache,
			func() evidence.Target {
				x := localTarget()
				x.Archives = []evidence.Artifact{{Path: "/cache/numpy-2-build_0.conda", Bytes: 12}}
				x.Extracted = []evidence.Artifact{{Path: "/cache/numpy-2-build_0", Bytes: 34}}
				return x
			},
			func() evidence.Target { return localTarget() },
			func() evidence.Target { x := localTarget(); x.Coverage["host-cache"] = evidence.Partial; return x }},
		{"ENV009", checkPythonEOL,
			func() evidence.Target { return localTarget(localRecord("python", "3.10.16")) },
			func() evidence.Target { return localTarget(localRecord("python", "3.14.0")) },
			func() evidence.Target {
				x := localTarget(localRecord("python", "3.14.0"))
				x.AsOf = time.Time{}
				return x
			}},
		{"ENV010", checkInstalledLock,
			func() evidence.Target {
				x := localTarget()
				x.Lock = &evidence.LockComparison{Path: "/proj/pixi.lock", Prefix: "/env", Environment: "default", Subdir: "linux-64", Report: &gorattler.SyncReport{Scope: "conda", Complete: true, Missing: []gorattler.LockedPackage{{Name: "numpy"}}}}
				return x
			},
			func() evidence.Target {
				x := localTarget()
				x.Lock = &evidence.LockComparison{Path: "/proj/pixi.lock", Prefix: "/env", Report: &gorattler.SyncReport{Scope: "conda", Complete: true, Matches: true}}
				return x
			},
			func() evidence.Target {
				x := localTarget()
				x.Lock = &evidence.LockComparison{Path: "/proj/pixi.lock", Prefix: "/env", Reason: "unreadable"}
				x.Coverage["installed-lock"] = evidence.Partial
				return x
			}},
		{"ENV012", checkRequestedSpecs,
			func() evidence.Target {
				a := localRecord("numpy", "2")
				a.Record.RequestedSpec = "numpy"
				return localTarget(a)
			},
			func() evidence.Target {
				a := localRecord("numpy", "2")
				a.Record.RequestedSpec = "numpy >=1"
				return localTarget(a)
			},
			func() evidence.Target {
				a := localRecord("numpy", "2")
				a.Record.RequestedSpec = "numpy ["
				return localTarget(a)
			}},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			rule := mustRule(t, tt.id)
			if reflect.ValueOf(rule.Check).Pointer() != reflect.ValueOf(tt.check).Pointer() {
				t.Fatalf("registry callback for %s does not match its behavior fixtures", tt.id)
			}
			for _, test := range []struct {
				name   string
				target evidence.Target
				status Status
				count  int
			}{
				{"positive", tt.positive(), FindingStatus, 1}, {"negative", tt.negative(), Pass, 0}, {"unknown", tt.unknown(), Unknown, 0},
			} {
				t.Run(test.name, func(t *testing.T) {
					outcome, findings := runLocalCheck(test.target, tt.id, tt.check)
					if outcome.Status != test.status || len(findings) != test.count {
						t.Fatalf("status=%s findings=%d, want %s/%d; reason=%s", outcome.Status, len(findings), test.status, test.count, outcome.Reason)
					}
					for _, finding := range findings {
						if finding.Message == "" || finding.Fingerprint == "" || len(finding.Evidence.Paths) == 0 || !strings.Contains(finding.Message, finding.Evidence.Paths[0]) {
							t.Errorf("finding needs message, fingerprint and a displayed path: %+v", finding)
						}
					}
				})
			}
		})
	}
}

func TestPipOwnershipAndShadowMapping(t *testing.T) {
	for _, tt := range []struct {
		name    string
		records []inventory.CondaRecord
		python  []evidence.PythonDistribution
		status  Status
		count   int
		text    string
	}{
		{"renamed owner maps distribution", []inventory.CondaRecord{localRecord("vendor-bundle", "90")}, []evidence.PythonDistribution{localDistribution("Some.Project", "1", "vendor-bundle"), localDistribution("some_project", "2", "")}, FindingStatus, 1, "distribution metadata"},
		{"owner version need not equal distribution", []inventory.CondaRecord{localRecord("vendor-bundle", "90")}, []evidence.PythonDistribution{localDistribution("Some.Project", "1", "vendor-bundle")}, Pass, 0, ""},
		{"own metadata mismatch", []inventory.CondaRecord{localRecord("numpy", "2")}, []evidence.PythonDistribution{localDistribution("numpy", "3", "numpy")}, FindingStatus, 1, "owning conda"},
		{"name-only differing fallback", []inventory.CondaRecord{localRecord("some-project", "1")}, []evidence.PythonDistribution{localDistribution("Some_Project", "2", "")}, Unknown, 0, ""},
		{"name-only equal fallback", []inventory.CondaRecord{localRecord("some-project", "1")}, []evidence.PythonDistribution{localDistribution("Some_Project", "1.0", "")}, Unknown, 0, ""},
		{"unrelated conda package is not mapping", []inventory.CondaRecord{localRecord("libxml2", "2")}, []evidence.PythonDistribution{localDistribution("lxml", "3", "")}, Pass, 0, ""},
		{"missing owner record", []inventory.CondaRecord{localRecord("numpy", "2")}, []evidence.PythonDistribution{localDistribution("numpy", "2", "missing")}, Unknown, 0, ""},
		{"invalid Python name", []inventory.CondaRecord{localRecord("numpy", "2")}, []evidence.PythonDistribution{localDistribution("bad name!", "2", "")}, Unknown, 0, ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			x := localTarget(tt.records...)
			x.Python = tt.python
			outcome, findings := runLocalCheck(x, "ENV004", checkPipShadows)
			if outcome.Status != tt.status || len(findings) != tt.count {
				t.Fatalf("outcome=%+v findings=%+v", outcome, findings)
			}
			if len(findings) > 0 && !strings.Contains(findings[0].Message, tt.text) {
				t.Fatalf("message lacks %q: %s", tt.text, findings[0].Message)
			}
		})
	}
	x := localTarget(localRecord("numpy", "2"))
	x.Python = []evidence.PythonDistribution{localDistribution("click", "8", "")}
	_, findings := runLocalCheck(x, "ENV003", checkPipInstalled)
	if len(findings) != 1 || !strings.Contains(findings[0].Message, "outside conda") || strings.Contains(findings[0].Message, "pip-installed") {
		t.Fatalf("unowned metadata must not identify its installer: %+v", findings)
	}
}

func TestWorkingBaseDependencyClosure(t *testing.T) {
	for _, tt := range []struct {
		name    string
		deps    []string
		records []inventory.CondaRecord
		status  Status
		count   int
	}{
		{"transitive", []string{"python >=3.11"}, func() []inventory.CondaRecord {
			p := localRecord("python", "3.14")
			p.Record.Depends = []string{"openssl >=3"}
			return []inventory.CondaRecord{p, localRecord("openssl", "3")}
		}(), Pass, 0},
		{"cycle", []string{"python"}, func() []inventory.CondaRecord {
			p := localRecord("python", "3.14")
			p.Record.Depends = []string{"conda"}
			return []inventory.CondaRecord{p}
		}(), Pass, 0},
		{"virtual dependency", []string{"__glibc >=2.17"}, nil, Pass, 0},
		{"invalid dependency", []string{"num*py"}, []inventory.CondaRecord{localRecord("numpy", "2")}, Unknown, 0},
		{"missing dependency", []string{"missing >=1"}, []inventory.CondaRecord{localRecord("numpy", "2")}, Unknown, 0},
		{"invalid installed name", nil, []inventory.CondaRecord{localRecord("bad name!", "2")}, Unknown, 0},
		{"duplicate installed name", nil, []inventory.CondaRecord{localRecord("conda", "25")}, Unknown, 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := localRecord("conda", "24")
			c.Record.Depends = tt.deps
			x := localTarget(append([]inventory.CondaRecord{c}, tt.records...)...)
			outcome, findings := runLocalCheck(x, "ENV005", checkWorkingBase)
			if outcome.Status != tt.status || len(findings) != tt.count {
				t.Fatalf("outcome=%+v findings=%+v", outcome, findings)
			}
			if outcome.Status == Pass && !strings.Contains(outcome.Reason, "candidate") {
				t.Fatalf("tooling presence does not prove base: %+v", outcome)
			}
		})
	}
	for _, root := range []string{"conda", "mamba", "micromamba"} {
		x := localTarget(localRecord(root, "1"), localRecord("numpy", "2"))
		_, findings := runLocalCheck(x, "ENV005", checkWorkingBase)
		if len(findings) != 1 || !strings.Contains(findings[0].Message, "tooling/base candidate") {
			t.Fatalf("%s: %+v", root, findings)
		}
	}
}

func TestDuplicateIdentitySafety(t *testing.T) {
	for _, tt := range []struct {
		name   string
		change func(*evidence.Prefix)
		status Status
		count  int
	}{
		{"files are outside comparison", func(p *evidence.Prefix) { p.Records[0].Record.Files = []string{"different"} }, FindingStatus, 1},
		{"canonical channel", func(p *evidence.Prefix) { p.Records[0].Record.Channel = "https://conda.anaconda.org/conda-forge/" }, FindingStatus, 1},
		{"canonical version", func(p *evidence.Prefix) { p.Records[0].Record.Version = "2.0" }, FindingStatus, 1},
		{"build", func(p *evidence.Prefix) { p.Records[0].Record.Build = "another" }, Pass, 0},
		{"build number", func(p *evidence.Prefix) { p.Records[0].Record.BuildNumber = 1 }, Pass, 0},
		{"channel", func(p *evidence.Prefix) { p.Records[0].Record.Channel = "other" }, Pass, 0},
		{"subdir", func(p *evidence.Prefix) { p.Records[0].Record.Subdir = "osx-arm64" }, Pass, 0},
		{"hash", func(p *evidence.Prefix) { p.Records[0].Record.SHA256 = strings.Repeat("b", 64) }, Pass, 0},
		{"missing hash", func(p *evidence.Prefix) { p.Records[0].Record.SHA256 = "" }, Unknown, 0},
		{"invalid hash", func(p *evidence.Prefix) { p.Records[0].Record.SHA256 = "bad" }, Unknown, 0},
		{"incomplete peer", func(p *evidence.Prefix) { p.RecordCoverage = evidence.Partial }, Unknown, 0},
		{"empty peer", func(p *evidence.Prefix) { p.Records = nil }, Unknown, 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			x := localTarget(localRecord("numpy", "2"))
			peer := evidence.Prefix{Path: "/other", RecordCoverage: evidence.Complete, Records: []inventory.CondaRecord{localRecord("numpy", "2")}}
			tt.change(&peer)
			x.Peers = []evidence.Prefix{x.Prefixes[0], peer}
			outcome, findings := runLocalCheck(x, "ENV006", checkDuplicates)
			if outcome.Status != tt.status || len(findings) != tt.count {
				t.Fatalf("outcome=%+v findings=%+v", outcome, findings)
			}
			if len(findings) > 0 && (!strings.Contains(findings[0].Message, "conda package metadata") || !slices.Contains(findings[0].Evidence.Paths, "/other")) {
				t.Fatalf("wrong duplicate claim: %+v", findings)
			}
		})
	}
	x := localTarget(localRecord("numpy", "2"))
	x.Prefixes[0].Records[0].Record.SHA256 = ""
	peer := evidence.Prefix{Path: "/other", RecordCoverage: evidence.Complete, Records: []inventory.CondaRecord{localRecord("numpy", "2")}}
	peer.Records[0].Record.SHA256 = ""
	x.Peers = []evidence.Prefix{x.Prefixes[0], peer}
	if _, findings := runLocalCheck(x, "ENV006", checkDuplicates); len(findings) != 1 {
		t.Fatal("complete matching metadata with no reported hashes on either side should be a candidate")
	}
}

func TestMixedChannelsCanonicalBoundariesAndRedaction(t *testing.T) {
	for _, tt := range []struct {
		channel string
		status  Status
		count   int
	}{
		{"https://repo.anaconda.com/pkgs/r/linux-64", FindingStatus, 1},
		{"https://user:SECRET@repo.anaconda.com/pkgs/main?token=TOKEN", FindingStatus, 1},
		{"https://example.com/repo.anaconda.com/pkgs/main", Pass, 0},
		{"https://repo.anaconda.com.evil.invalid/pkgs/main", Pass, 0},
		{"https://repo.anaconda.com/pkgs/main-extra", Pass, 0},
		{"https://conda.anaconda.org/conda-forge-extra", Pass, 0},
		{"defaults", Unknown, 0},
		{"https://user:SECRET@[bad/channel", Unknown, 0},
	} {
		t.Run(tt.channel, func(t *testing.T) {
			a := localRecord("python", "3.14")
			a.Record.Channel = tt.channel
			x := localTarget(a, localRecord("numpy", "2"))
			outcome, findings := runLocalCheck(x, "ENV007", checkMixedChannels)
			if outcome.Status != tt.status || len(findings) != tt.count {
				t.Fatalf("outcome=%+v findings=%+v", outcome, findings)
			}
			body, _ := json.Marshal(struct {
				Outcome  Outcome
				Findings []Finding
			}{outcome, findings})
			if strings.Contains(string(body), "SECRET") || strings.Contains(string(body), "TOKEN") {
				t.Fatalf("credentials leaked: %s", body)
			}
		})
	}
}

func TestHostCacheLogicalBytesAndBoundedPaths(t *testing.T) {
	x := localTarget()
	for i := range MaxSamples + 3 {
		x.Archives = append(x.Archives, evidence.Artifact{Path: fmt.Sprintf("/cache/%02d.conda", i), Bytes: 2})
	}
	x.Extracted = []evidence.Artifact{{Path: "/cache/unpacked", Bytes: 50}}
	x.Coverage["host-cache"] = evidence.Partial
	_, findings := runLocalCheck(x, "ENV008", checkHostCache)
	if len(findings) != 1 {
		t.Fatalf("findings=%+v", findings)
	}
	f := findings[0]
	if len(f.Evidence.Paths) != MaxSamples || len(f.Evidence.Samples) != MaxSamples || f.Evidence.Count != MaxSamples+4 || f.Evidence.PayloadBytes != int64((MaxSamples+3)*2) {
		t.Fatalf("unbounded or wrong accounting: %+v", f)
	}
	if !strings.Contains(f.Evidence.ByteUnit, "extracted directory sizes are not measured") || !strings.Contains(f.Evidence.ByteUnit, "not unique or reclaimable") {
		t.Fatalf("logical totals must not promise reclaimable bytes: %+v", f)
	}
	rule := mustRule(t, "ENV008")
	for _, want := range []string{"conda clean --tarballs --dry-run", "conda clean --packages --dry-run"} {
		if !strings.Contains(rule.Fix, want) {
			t.Errorf("missing safe command %q: %s", want, rule.Fix)
		}
	}
	if strings.Contains(f.Message, "will reclaim") {
		t.Fatal("cache bytes are not guaranteed savings")
	}
}

func TestPythonEOLDateAndCoverageBoundaries(t *testing.T) {
	for _, tt := range []struct {
		version, date string
		status        Status
		count         int
	}{
		{"3.10.16", "2026-09-30", Pass, 0}, {"3.10.16", "2026-10-01", FindingStatus, 1},
		{"3.9.23", "2025-10-30", Pass, 0}, {"3.9.23", "2025-10-31", FindingStatus, 1},
		{"2.7.18", "2026-10-26", FindingStatus, 1}, {"3.11.14", "2026-10-26", Pass, 0},
		{"3.11.14", "2027-10-01", Unknown, 0}, {"3.16.0", "2026-10-26", Unknown, 0},
		{"bad version!", "2026-10-26", Unknown, 0},
	} {
		t.Run(tt.version+"/"+tt.date, func(t *testing.T) {
			x := localTarget(localRecord("python", tt.version))
			x.AsOf, _ = time.Parse(time.DateOnly, tt.date)
			outcome, findings := runLocalCheck(x, "ENV009", checkPythonEOL)
			if outcome.Status != tt.status || len(findings) != tt.count {
				t.Fatalf("outcome=%+v findings=%+v", outcome, findings)
			}
			if len(findings) > 0 && !strings.Contains(findings[0].Message, "upstream") {
				t.Fatal("EOL claim must scope support to upstream")
			}
		})
	}
	x := localTarget(localRecord("python", "3.10.16"))
	x.Coverage["conda-records"] = evidence.Partial
	x.Prefixes[0].RecordCoverage = evidence.Partial
	if _, findings := runLocalCheck(x, "ENV009", checkPythonEOL); len(findings) != 1 {
		t.Fatal("positive observed Python EOL survives partial enumeration")
	}
}

func TestInstalledLockReportSemantics(t *testing.T) {
	for _, tt := range []struct {
		name   string
		report *gorattler.SyncReport
		status Status
		count  int
	}{
		{"extra", &gorattler.SyncReport{Scope: "conda", Complete: true, Extra: []gorattler.InstalledPackage{{Name: "click", Version: "8"}}}, FindingStatus, 1},
		{"changed", &gorattler.SyncReport{Scope: "conda", Complete: true, Changed: []gorattler.PackageChange{{Locked: gorattler.LockedPackage{Name: "numpy", Version: "1"}, Installed: gorattler.InstalledPackage{Name: "numpy", Version: "2"}}}}, FindingStatus, 1},
		{"positive with unknown", &gorattler.SyncReport{Scope: "conda", Missing: []gorattler.LockedPackage{{Name: "numpy"}}, Unknown: []gorattler.ComparisonIssue{{Name: "python", Reason: "missing hash"}}}, FindingStatus, 1},
		{"false match is not evidence", &gorattler.SyncReport{Scope: "conda", Complete: true, Matches: false}, Unknown, 0},
		{"unknown even if matches true", &gorattler.SyncReport{Scope: "conda", Complete: true, Matches: true, Unknown: []gorattler.ComparisonIssue{{Name: "python"}}}, Unknown, 0},
		{"different comparison scope", &gorattler.SyncReport{Scope: "conda+pypi", Complete: true, Matches: true}, Unknown, 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			x := localTarget()
			x.Lock = &evidence.LockComparison{Path: "/proj/pixi.lock", Prefix: "/env", Environment: "default", Subdir: "linux-64", Report: tt.report}
			outcome, findings := runLocalCheck(x, "ENV010", checkInstalledLock)
			if outcome.Status != tt.status || len(findings) != tt.count {
				t.Fatalf("outcome=%+v findings=%+v", outcome, findings)
			}
		})
	}
	x := localTarget()
	if outcome, _ := runLocalCheck(x, "ENV010", checkInstalledLock); outcome.Status != NotApplicable {
		t.Fatalf("no selected installed lock should be N/A: %+v", outcome)
	}
	x.Lock = &evidence.LockComparison{Path: "/proj/pixi.lock", Prefix: "/env", Report: &gorattler.SyncReport{Scope: "conda", Complete: true, Matches: true}}
	if outcome, _ := runLocalCheck(x, "ENV010", checkInstalledLock); outcome.Status != Pass || !strings.Contains(outcome.Reason, "conda") || !strings.Contains(outcome.Reason, "files") {
		t.Fatalf("pass must retain metadata-only scope: %+v", outcome)
	}
}

func TestRequestedSpecsConstraintsNotPinnedBoolean(t *testing.T) {
	for _, tt := range []struct {
		spec   string
		status Status
		count  int
	}{
		{"numpy", FindingStatus, 1}, {"numpy *", FindingStatus, 1}, {"numpy[build=build_0]", FindingStatus, 1},
		{"numpy >=1", Pass, 0}, {"numpy <3", Pass, 0}, {"numpy !=1", Pass, 0}, {"numpy==2", Pass, 0}, {"numpy 2.*", Pass, 0},
		{"numpy==2 build_0", Pass, 0}, {"", NotApplicable, 0}, {"other", Unknown, 0},
	} {
		t.Run(tt.spec, func(t *testing.T) {
			a := localRecord("numpy", "2")
			a.Record.RequestedSpec = tt.spec
			outcome, findings := runLocalCheck(localTarget(a), "ENV012", checkRequestedSpecs)
			if outcome.Status != tt.status || len(findings) != tt.count {
				t.Fatalf("outcome=%+v findings=%+v", outcome, findings)
			}
		})
	}
	a := localRecord("numpy", "2")
	a.Record.RequestedSpecs = []string{"numpy >=1", "numpy", "numpy"}
	_, findings := runLocalCheck(localTarget(a), "ENV012", checkRequestedSpecs)
	if len(findings) != 1 || findings[0].Evidence.Count != 1 {
		t.Fatalf("multiple specs for one record must not inflate package count: %+v", findings)
	}
}

func TestLocalChecksDoNotMutateFacts(t *testing.T) {
	x := localTarget(localRecord("numpy", "2"), localRecord("conda", "24"), localRecord("python", "3.10"))
	x.Python = []evidence.PythonDistribution{localDistribution("numpy", "2", "numpy"), localDistribution("numpy", "3", "")}
	x.Archives = []evidence.Artifact{{Path: "/z", Bytes: 2}, {Path: "/a", Bytes: 3}}
	x.Peers = []evidence.Prefix{x.Prefixes[0], {Path: "/other", Records: slices.Clone(x.Prefixes[0].Records), RecordCoverage: evidence.Complete}}
	before, _ := json.Marshal(struct {
		Target          evidence.Target
		Prefixes, Peers []evidence.Prefix
		Records         []inventory.CondaRecord
	}{x, x.Prefixes, x.Peers, x.Prefixes[0].Records})
	for _, check := range []func(evidence.Target, RuleOptions, Rule) (Outcome, []Finding){checkPipInstalled, checkPipShadows, checkWorkingBase, checkDuplicates, checkMixedChannels, checkHostCache, checkPythonEOL, checkInstalledLock, checkRequestedSpecs} {
		runLocalCheck(x, "TST", check)
	}
	after, _ := json.Marshal(struct {
		Target          evidence.Target
		Prefixes, Peers []evidence.Prefix
		Records         []inventory.CondaRecord
	}{x, x.Prefixes, x.Peers, x.Prefixes[0].Records})
	if string(before) != string(after) {
		t.Fatal("pure callbacks mutated input facts")
	}
}

func TestLocalChecksEmptyAndPartialSubjects(t *testing.T) {
	for _, tt := range []struct {
		id    string
		check func(evidence.Target, RuleOptions, Rule) (Outcome, []Finding)
	}{
		{"ENV003", checkPipInstalled}, {"ENV004", checkPipShadows}, {"ENV005", checkWorkingBase},
		{"ENV006", checkDuplicates}, {"ENV007", checkMixedChannels}, {"ENV008", checkHostCache},
		{"ENV009", checkPythonEOL}, {"ENV010", checkInstalledLock}, {"ENV012", checkRequestedSpecs},
	} {
		t.Run(tt.id, func(t *testing.T) {
			x := localTarget()
			x.Prefixes = nil
			if outcome, findings := runLocalCheck(x, tt.id, tt.check); outcome.Status != NotApplicable || len(findings) != 0 {
				t.Fatalf("complete empty scope: outcome=%+v findings=%+v", outcome, findings)
			}
			x.Coverage["prefixes"] = evidence.Partial
			x.Coverage["host-cache"] = evidence.Partial
			x.Coverage["installed-lock"] = evidence.Partial
			if outcome, findings := runLocalCheck(x, tt.id, tt.check); outcome.Status != Unknown || len(findings) != 0 {
				t.Fatalf("partial empty scope: outcome=%+v findings=%+v", outcome, findings)
			}
		})
	}
}

func TestLocalUnknownBranches(t *testing.T) {
	tests := []struct {
		name, id string
		check    func(evidence.Target, RuleOptions, Rule) (Outcome, []Finding)
		target   func() evidence.Target
	}{
		{"Python coverage", "ENV003", checkPipInstalled, func() evidence.Target {
			x := localTarget(localRecord("numpy", "2"))
			x.Coverage["python-distributions"] = evidence.Partial
			return x
		}},
		{"metadata path absent", "ENV003", checkPipInstalled, func() evidence.Target {
			x := localTarget()
			x.Python = []evidence.PythonDistribution{{Name: "numpy", Version: "2"}}
			return x
		}},
		{"name invalid", "ENV003", checkPipInstalled, func() evidence.Target {
			x := localTarget()
			x.Python = []evidence.PythonDistribution{localDistribution("invalid name", "2", "")}
			return x
		}},
		{"Python partial shadow", "ENV004", checkPipShadows, func() evidence.Target {
			x := localTarget()
			x.Coverage["python-distributions"] = evidence.Partial
			return x
		}},
		{"bad conda name shadow", "ENV004", checkPipShadows, func() evidence.Target { return localTarget(localRecord("conda >=1", "1")) }},
		{"bad conda version shadow", "ENV004", checkPipShadows, func() evidence.Target {
			x := localTarget(localRecord("numpy", "invalid version!"))
			x.Python = []evidence.PythonDistribution{localDistribution("numpy", "2", "numpy")}
			return x
		}},
		{"ambiguous fallback", "ENV004", checkPipShadows, func() evidence.Target {
			x := localTarget(localRecord("some-project", "2"), localRecord("some_project", "3"))
			x.Python = []evidence.PythonDistribution{localDistribution("some.project", "4", "")}
			return x
		}},
		{"ownership partial suppresses fallback", "ENV004", checkPipShadows, func() evidence.Target {
			x := localTarget(localRecord("numpy", "2"))
			x.Python = []evidence.PythonDistribution{localDistribution("numpy", "3", "")}
			x.Prefixes[0].RecordCoverage = evidence.Partial
			return x
		}},
		{"Python ownership partial suppresses orphan", "ENV004", checkPipShadows, func() evidence.Target {
			x := localTarget(localRecord("numpy", "2"))
			x.Python = []evidence.PythonDistribution{localDistribution("numpy", "2", "numpy"), localDistribution("numpy", "3", "")}
			x.Coverage["python-distributions"] = evidence.Partial
			return x
		}},
		{"tooling incomplete", "ENV005", checkWorkingBase, func() evidence.Target {
			x := localTarget(localRecord("conda", "24"), localRecord("numpy", "2"))
			x.Prefixes[0].RecordCoverage = evidence.Partial
			return x
		}},
		{"peer input missing", "ENV006", checkDuplicates, func() evidence.Target { return localTarget(localRecord("numpy", "2")) }},
		{"duplicate conda names", "ENV006", checkDuplicates, func() evidence.Target {
			x := localTarget(localRecord("numpy", "2"), localRecord("NumPy", "2"))
			x.Peers = []evidence.Prefix{x.Prefixes[0]}
			return x
		}},
		{"record version invalid", "ENV006", checkDuplicates, func() evidence.Target {
			x := localTarget(localRecord("numpy", "invalid version!"))
			x.Peers = []evidence.Prefix{x.Prefixes[0]}
			return x
		}},
		{"EOL name invalid", "ENV009", checkPythonEOL, func() evidence.Target { return localTarget(localRecord("python >=3.11", "3.11")) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			outcome, findings := runLocalCheck(tt.target(), tt.id, tt.check)
			if outcome.Status != Unknown || len(findings) != 0 {
				t.Fatalf("outcome=%+v findings=%+v", outcome, findings)
			}
		})
	}
}

func TestKnownDifferencesAndHashGapsAreOrderIndependent(t *testing.T) {
	x := localTarget(localRecord("numpy", "2"), localRecord("python", "3.14"))
	peer := evidence.Prefix{Path: "/other", RecordCoverage: evidence.Complete, Records: []inventory.CondaRecord{localRecord("numpy", "3"), localRecord("python", "3.14")}}
	peer.Records[1].Record.SHA256 = ""
	x.Peers = []evidence.Prefix{x.Prefixes[0], peer}
	first, _ := runLocalCheck(x, "ENV006", checkDuplicates)
	if first.Status != Unknown {
		t.Fatalf("a hash gap must not become an all-clear because another package differs: %+v", first)
	}
	for range 100 {
		got, findings := runLocalCheck(x, "ENV006", checkDuplicates)
		if got.Status != first.Status || got.Reason != first.Reason || len(findings) != 0 {
			t.Fatalf("order-dependent result: %+v vs %+v", first, got)
		}
	}
}

func TestInstalledLockConcreteActionIsShellScoped(t *testing.T) {
	x := localTarget()
	x.Lock = &evidence.LockComparison{Path: "/proj/pixi.lock", Prefix: "/env", Environment: "x';& touch BAD", Subdir: "linux-64", Report: &gorattler.SyncReport{Scope: "conda", Complete: true, Extra: []gorattler.InstalledPackage{{Name: "numpy"}}}}
	_, findings := runLocalCheck(x, "ENV010", checkInstalledLock)
	if len(findings) != 1 {
		t.Fatalf("findings=%+v", findings)
	}
	if runtime.GOOS == "windows" {
		if findings[0].Next != "" {
			t.Fatalf("Windows must use generic action: %s", findings[0].Next)
		}
	} else if !strings.Contains(findings[0].Next, "POSIX shell") || !strings.Contains(findings[0].Next, "'x'\\'';& touch BAD'") {
		t.Fatalf("concrete command must be quoted and shell scoped: %s", findings[0].Next)
	}
}

func TestOwnedPEP440EquivalentVersionsDoNotFire(t *testing.T) {
	x := localTarget(localRecord("python-dateutil", "2.9.0post0"))
	x.Python = []evidence.PythonDistribution{localDistribution("python-dateutil", "2.9.0.post0", "python-dateutil")}
	outcome, findings := runLocalCheck(x, "ENV004", checkPipShadows)
	if len(findings) != 0 || outcome.Status == FindingStatus {
		t.Fatalf("PEP 440 equivalent versions must not fire: outcome=%+v findings=%+v", outcome, findings)
	}
}

func TestOwnedPEP440InvalidVersionIsUnknown(t *testing.T) {
	x := localTarget(localRecord("numpy", "2"))
	x.Python = []evidence.PythonDistribution{localDistribution("numpy", "not a version!", "numpy")}
	outcome, findings := runLocalCheck(x, "ENV004", checkPipShadows)
	if len(findings) != 0 || outcome.Status != Unknown {
		t.Fatalf("invalid PEP 440 must be unknown: outcome=%+v findings=%+v", outcome, findings)
	}
}

func TestOwnedPEP440PrereleaseAndRealDifference(t *testing.T) {
	for _, tt := range []struct {
		conda, meta string
		status      Status
		count       int
	}{
		{"1.0rc1", "1.0c1", Pass, 0},
		{"1.0a1", "1.0alpha1", Pass, 0},
		{"2.0.post1", "2.0-post1", Pass, 0},
		{"2.0", "2.1", FindingStatus, 1},
	} {
		x := localTarget(localRecord("numpy", tt.conda))
		x.Python = []evidence.PythonDistribution{localDistribution("numpy", tt.meta, "numpy")}
		outcome, findings := runLocalCheck(x, "ENV004", checkPipShadows)
		if outcome.Status != tt.status || len(findings) != tt.count {
			t.Fatalf("conda %s vs meta %s: outcome=%+v findings=%d", tt.conda, tt.meta, outcome, len(findings))
		}
	}
}

func TestDuplicateGroupReportedOncePerTarget(t *testing.T) {
	x := localTarget(localRecord("numpy", "2"))
	// The same prefix appears twice in the target and once as a peer.
	x.Prefixes = append(x.Prefixes, x.Prefixes[0])
	peer := evidence.Prefix{Path: "/other", RecordCoverage: evidence.Complete, Records: []inventory.CondaRecord{localRecord("numpy", "2")}}
	x.Peers = []evidence.Prefix{x.Prefixes[0], peer}
	outcome, findings := runLocalCheck(x, "ENV006", checkDuplicates)
	if len(findings) != 1 || outcome.Status != FindingStatus {
		t.Fatalf("one duplicate group must yield one finding: outcome=%+v findings=%d", outcome, len(findings))
	}
}

func TestDuplicateGroupsKeepValidCrossTargetReports(t *testing.T) {
	a := localTarget(localRecord("numpy", "2"))
	a.Peers = []evidence.Prefix{a.Prefixes[0], {Path: "/other", RecordCoverage: evidence.Complete, Records: []inventory.CondaRecord{localRecord("numpy", "2")}}}
	b := localTarget(localRecord("numpy", "2"))
	b.ID = "other-target"
	b.Prefixes[0].Path = "/other"
	b.Peers = a.Peers
	for _, target := range []evidence.Target{a, b} {
		outcome, findings := runLocalCheck(target, "ENV006", checkDuplicates)
		if len(findings) == 0 || outcome.Status != FindingStatus {
			t.Fatalf("target %s lost its valid duplicate report: outcome=%+v findings=%d", target.ID, outcome, len(findings))
		}
	}
}
