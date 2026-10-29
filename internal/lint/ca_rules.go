package lint

import (
	"fmt"
	"net/url"
	"path/filepath"
	"runtime"
	"strings"

	pep440 "github.com/aquasecurity/go-pep440-version"
	"github.com/conda-incubator/envscout/internal/evidence"
	gorattler "github.com/conda-incubator/go-rattler"
)

// Minimums are the distribution recommendations verified on 2026-10-26, not
// universal vulnerability ranges. certifi 2026.10.18 already fixes the incident.
func caPackageMinimum(record gorattler.PrefixRecord) (minimum, channel string) {
	canonical, valid := localChannel(record)
	if !valid {
		return "", ""
	}
	u, err := url.Parse(canonical)
	if err != nil {
		return "", ""
	}
	switch {
	case strings.EqualFold(u.Host, "conda.anaconda.org") && u.Path == "/conda-forge/":
		channel = "conda-forge"
	case strings.EqualFold(u.Host, "repo.anaconda.com") && u.Path == "/pkgs/main/":
		channel = "defaults"
	default:
		return "", ""
	}
	minimum = "2026.10.19"
	if record.Name == "ca-certificates" && channel == "defaults" {
		minimum = "2026.10.20"
	}
	return minimum, channel
}

func checkCAPackages(target evidence.Target, opts RuleOptions, rule Rule) (Outcome, []Finding) {
	if target.IsVirtualenv() {
		return checkVirtualenvCertifi(target, opts, rule)
	}
	outcome := localRecordOutcome(target)
	outcome.SubjectCount = 0
	var findings []Finding
	for _, prefix := range sortedLocalPrefixes(target) {
		for _, located := range prefix.Records {
			record := located.Record
			if record.Name != "certifi" && record.Name != "ca-certificates" {
				continue
			}
			outcome.SubjectCount++
			if located.Path == "" || prefix.Path == "" {
				outcome.Status, outcome.Reason = Unknown, "a CA package has no prefix or metadata source path"
				continue
			}
			minimum, channel := caPackageMinimum(record)
			if minimum == "" {
				outcome.Status, outcome.Reason = Unknown, "CA package remediation minimum is unknown for the recorded channel"
				continue
			}
			comparison, err := gorattler.CompareVersions(record.Version, minimum)
			if record.Version == "" || err != nil {
				outcome.Status, outcome.Reason = Unknown, "a CA package version could not be compared with its remediation minimum"
				continue
			}
			if comparison >= 0 {
				continue
			}
			if len(findings) >= MaxFindings {
				outcome.limited = true
				outcome.Status, outcome.Reason = Unknown, "CA package evaluation limit reached; remaining packages were not compared"
				return outcome, findings
			}
			finding := newFinding(target, rule, opts.Severity, []string{located.Path}, nil)
			finding.Evidence.Count = 1
			finding.Message = fmt.Sprintf("%s %s in %s, recorded at %s, is below the %s recommended minimum %s following the October 2026 eMudhra incident. Update this environment's CA package independently of base.", record.Name, record.Version, quotedPaths([]string{prefix.Path}), quotedPaths(finding.Evidence.Paths), channel, minimum)
			if record.Name == "certifi" && record.Version == "2026.10.18" {
				finding.Message += " This release already contains the upstream security fix; the recommendation also restores unaffected roots."
			}
			source := "https://conda.anaconda.org/conda-forge"
			if channel == "defaults" {
				source = "https://repo.anaconda.com/pkgs/main"
			}
			command := fmt.Sprintf("conda install --prefix %s %s", commandArg(prefix.Path), commandArg(source+"::"+record.Name+">="+minimum))
			switch {
			case target.Kind == "oci-archive":
				finding.Next = "Update the CA package in the image build using the recommended minimum, then rebuild the image. " + rule.Fix
			case runtime.GOOS != "windows":
				finding.Next = fmt.Sprintf("In a POSIX shell, run `%s`. Keep certificate verification enabled; if Python or package pins block the update, recreate on a supported platform/Python version.", command)
			default:
				finding.Next = fmt.Sprintf("For prefix %s, install %s>=%s from %s with conda or the project's package manager. Keep certificate verification enabled.", quotedPaths([]string{prefix.Path}), record.Name, minimum, channel)
			}
			findings = append(findings, finding)
		}
	}
	if outcome.Status == Pass {
		if outcome.SubjectCount == 0 {
			outcome.Status, outcome.Reason = NotApplicable, "no certifi or ca-certificates conda package was found in the inspected prefixes"
		} else {
			outcome.Reason = "observed CA package versions meet the recorded channel's recommended minimums; certificate content and active trust are not inspected"
		}
	}
	return outcome, findings
}

func checkVirtualenvCertifi(target evidence.Target, opts RuleOptions, rule Rule) (Outcome, []Finding) {
	outcome := Outcome{Status: Pass}
	if !completeOf(target, "prefixes") || !completeOf(target, "python-distributions") {
		outcome.Status, outcome.Reason = Unknown, "virtualenv discovery or installed Python metadata coverage is incomplete"
	}
	prefix := target.Prefixes[0]
	const minimum = "2026.10.18"
	patched := pep440.MustParse(minimum)
	var findings []Finding
	for _, distribution := range target.Python {
		name, valid := canonicalPythonName(distribution.Name)
		if !valid || name != "certifi" {
			continue
		}
		outcome.SubjectCount++
		version, err := pep440.Parse(distribution.Version)
		if err != nil || !pythonWithin(prefix, distribution) {
			outcome.Status, outcome.Reason = Unknown, "virtualenv certifi has no comparable version or local metadata source path"
			continue
		}
		if !version.LessThan(patched) {
			continue
		}
		if len(findings) >= MaxFindings {
			outcome.limited = true
			outcome.Status, outcome.Reason = Unknown, "virtualenv certifi evaluation limit reached"
			return outcome, findings
		}
		finding := newFinding(target, rule, opts.Severity, []string{distribution.Path}, nil)
		finding.Evidence.Count = 1
		finding.Message = fmt.Sprintf("certifi %s in virtualenv %s, recorded at %s, is below the upstream patched minimum %s following the October 2026 eMudhra incident. Package metadata does not establish certificate contents or active trust.", distribution.Version, quotedPaths([]string{prefix.Path}), quotedPaths(finding.Evidence.Paths), minimum)
		if runtime.GOOS == "windows" {
			finding.Next = fmt.Sprintf("Use this virtualenv's interpreter at %s with `-m pip install --upgrade \"certifi>=%s\"`, or update its project specification and lock with the project's package manager. Keep certificate verification enabled.", quotedPaths([]string{filepath.Join(prefix.Path, "Scripts", "python.exe")}), minimum)
		} else {
			finding.Next = fmt.Sprintf("In a POSIX shell, run `%s -m pip install --upgrade %s`, or update this virtualenv's project specification and lock with its package manager. Keep certificate verification enabled.", commandArg(filepath.Join(prefix.Path, "bin", "python")), commandArg("certifi>="+minimum))
		}
		findings = append(findings, finding)
	}
	if outcome.Status == Pass {
		if outcome.SubjectCount == 0 {
			outcome.Status, outcome.Reason = NotApplicable, "no local certifi distribution metadata was found in the virtualenv; inherited and vendored bundles are not inspected"
		} else {
			outcome.Reason = "observed virtualenv certifi versions meet the upstream patched minimum; certificate content and active trust are not inspected"
		}
	}
	return outcome, findings
}
