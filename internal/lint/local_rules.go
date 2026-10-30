package lint

import (
	"fmt"
	"net/url"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"time"

	pep440 "github.com/aquasecurity/go-pep440-version"
	"github.com/conda-incubator/envscout/internal/evidence"
	"github.com/conda-incubator/envscout/internal/inventory"
	gorattler "github.com/conda-incubator/go-rattler"
)

// Record completeness is separate from discovery completeness: a valid observed
// package can support a positive finding even when another prefix was unreadable.
func localRecordOutcome(target evidence.Target) Outcome {
	outcome := Outcome{Status: Pass, SubjectCount: len(target.Prefixes)}
	if !completeOf(target, "prefixes") || !completeOf(target, "conda-records") {
		outcome.Status, outcome.Reason = Unknown, "prefix discovery or conda record coverage is incomplete"
	}
	for _, prefix := range target.Prefixes {
		if prefix.RecordCoverage != evidence.Complete {
			outcome.Status, outcome.Reason = Unknown, "conda record coverage is incomplete for "+prefix.Path
		}
	}
	if len(target.Prefixes) == 0 && outcome.Status == Pass {
		outcome.Status, outcome.Reason = NotApplicable, "no conda environment was found in the inspected scope"
	}
	return outcome
}

func sortedLocalPrefixes(target evidence.Target) []evidence.Prefix {
	prefixes := slices.Clone(target.Prefixes)
	slices.SortFunc(prefixes, func(a, b evidence.Prefix) int { return strings.Compare(a.Path, b.Path) })
	return prefixes
}

var pythonName = regexp.MustCompile(`^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$`)
var pythonSeparators = regexp.MustCompile(`[-_.]+`)

func canonicalPythonName(name string) (string, bool) {
	name = strings.ToLower(name)
	if !pythonName.MatchString(name) {
		return "", false
	}
	return pythonSeparators.ReplaceAllString(name, "-"), true
}

func canonicalCondaName(name string) (string, bool) {
	parsed, err := gorattler.ParseMatchSpec(name)
	return parsed.Name, err == nil && parsed.Name != "" && parsed.Name == strings.ToLower(name) && parsed.Version == "" && parsed.Build == ""
}

func pythonWithin(prefix evidence.Prefix, distribution evidence.PythonDistribution) bool {
	if prefix.Path == "" || distribution.Path == "" {
		return false
	}
	rel, err := filepath.Rel(prefix.Path, distribution.Path)
	return err == nil && filepath.IsLocal(rel)
}

func prefixOwnershipComplete(prefix evidence.Prefix) bool {
	return prefix.RecordCoverage == evidence.Complete && !slices.ContainsFunc(prefix.Records, func(record inventory.CondaRecord) bool {
		return !record.OwnershipKnown
	})
}

// Nested environments use their own ownership records, not the parent's.
func pythonPrefix(prefixes []evidence.Prefix, distribution evidence.PythonDistribution) (evidence.Prefix, bool) {
	var owner evidence.Prefix
	found := false
	for _, prefix := range prefixes {
		if pythonWithin(prefix, distribution) && (!found || len(prefix.Path) > len(owner.Path)) {
			owner, found = prefix, true
		}
	}
	return owner, found
}

func checkPipInstalled(target evidence.Target, opts RuleOptions, rule Rule) (Outcome, []Finding) {
	outcome := localRecordOutcome(target)
	if outcome.Status == NotApplicable {
		return outcome, nil
	}
	if !completeOf(target, "python-distributions") || (target.Coverage["conda-records"] != evidence.Complete && target.Coverage["conda-records"] != evidence.Partial) {
		outcome.Status, outcome.Reason = Unknown, "complete conda ownership and Python distribution metadata are required to establish absence of an owner"
		return outcome, nil
	}
	ownership := make(map[string]bool, len(target.Prefixes))
	for _, prefix := range target.Prefixes {
		ownership[prefix.Path] = prefixOwnershipComplete(prefix)
		if !ownership[prefix.Path] {
			outcome.Status, outcome.Reason = Unknown, "conda ownership metadata is incomplete for "+prefix.Path
		}
	}
	var paths []string
	for _, distribution := range target.Python {
		if distribution.Path == "" {
			outcome.Status, outcome.Reason = Unknown, "a Python distribution has no metadata path"
			continue
		}
		if distribution.OwnedBy != "" {
			continue
		}
		if _, valid := canonicalPythonName(distribution.Name); !valid {
			outcome.Status, outcome.Reason = Unknown, "a Python distribution has an invalid name"
			continue
		}
		if prefix, found := pythonPrefix(target.Prefixes, distribution); found && ownership[prefix.Path] {
			paths = append(paths, distribution.Path)
		}
	}
	if len(paths) == 0 {
		return outcome, nil
	}
	f := newFinding(target, rule, opts.Severity, paths, nil)
	f.Evidence.Count = len(paths)
	f.Message = fmt.Sprintf("%d Python distribution metadata entries at %s have no conda owner, evidence of installation outside conda. %s", len(paths), quotedPaths(f.Evidence.Paths), rule.Description)
	return outcome, []Finding{f}
}

// pythonVersionsDiffer compares two PEP 440 versions. It returns valid=false
// without comparing when either side is malformed, because the library panics
// on a zero-value Version.
func pythonVersionsDiffer(a, b string) (differs, valid bool) {
	aVersion, aErr := pep440.Parse(a)
	bVersion, bErr := pep440.Parse(b)
	if aErr != nil || bErr != nil {
		return false, false
	}
	return !aVersion.Equal(bVersion), true
}

func shadowFinding(target evidence.Target, opts RuleOptions, rule Rule, paths []string, message string) Finding {
	f := newFinding(target, rule, opts.Severity, paths, nil)
	f.Evidence.Count = 1
	f.Message = message + " Metadata at " + quotedPaths(f.Evidence.Paths) + ". " + rule.Description
	return f
}

func checkPipShadows(target evidence.Target, opts RuleOptions, rule Rule) (Outcome, []Finding) {
	outcome := localRecordOutcome(target)
	if outcome.Status == NotApplicable {
		return outcome, nil
	}
	if !completeOf(target, "python-distributions") {
		outcome.Status, outcome.Reason = Unknown, "Python distribution coverage is incomplete"
	}
	var findings []Finding
	comparisons := 0
	for _, prefix := range sortedLocalPrefixes(target) {
		ownershipComplete := prefixOwnershipComplete(prefix)
		if !ownershipComplete {
			outcome.Status, outcome.Reason = Unknown, "conda ownership metadata is incomplete for "+prefix.Path
		}
		byOwner := map[string][]inventory.CondaRecord{}
		byPythonName := map[string][]inventory.CondaRecord{}
		for _, record := range prefix.Records {
			name, valid := canonicalCondaName(record.Record.Name)
			if !valid {
				outcome.Status, outcome.Reason = Unknown, "a conda record has an invalid name"
				continue
			}
			byOwner[name] = append(byOwner[name], record)
			if python, valid := canonicalPythonName(name); valid {
				byPythonName[python] = append(byPythonName[python], record)
			}
		}
		owned := map[string][]evidence.PythonDistribution{}
		var orphans []evidence.PythonDistribution
		for _, distribution := range target.Python {
			if len(findings) >= MaxFindings {
				outcome.limited = true
				outcome.Status, outcome.Reason = Unknown, "Python conflict evaluation limit reached; remaining metadata was not compared"
				return outcome, findings
			}
			if ownerPrefix, found := pythonPrefix(target.Prefixes, distribution); !found || ownerPrefix.Path != prefix.Path {
				continue
			}
			name, valid := canonicalPythonName(distribution.Name)
			_, versionErr := pep440.Parse(distribution.Version)
			if !valid || versionErr != nil {
				outcome.Status, outcome.Reason = Unknown, "Python distribution name or version could not be compared"
				continue
			}
			if distribution.OwnedBy == "" {
				orphans = append(orphans, distribution)
				continue
			}
			owner, valid := canonicalCondaName(distribution.OwnedBy)
			if !valid || len(byOwner[owner]) != 1 {
				outcome.Status, outcome.Reason = Unknown, "Python metadata ownership does not identify one conda record"
				continue
			}
			owned[name] = append(owned[name], distribution)
			record := byOwner[owner][0]
			ownerName, _ := canonicalPythonName(owner)
			// Bundles can own differently named distributions with unrelated versions.
			if ownerName != name {
				continue
			}
			differs, valid := pythonVersionsDiffer(distribution.Version, record.Record.Version)
			if !valid {
				outcome.Status, outcome.Reason = Unknown, "owned metadata and conda versions could not be compared as PEP 440 versions"
			} else if differs {
				findings = append(findings, shadowFinding(target, opts, rule, []string{record.Path, distribution.Path}, fmt.Sprintf("Python distribution %s version %s differs from its owning conda package %s version %s.", distribution.Name, distribution.Version, owner, record.Record.Version)))
			}
		}
		// An orphan is established only after every conda ownership record was read.
		if !ownershipComplete || !completeOf(target, "conda-records") || !completeOf(target, "python-distributions") {
			continue
		}
		for _, orphan := range orphans {
			name, _ := canonicalPythonName(orphan.Name)
			if len(owned[name]) > 0 {
				for _, other := range owned[name] {
					if comparisons >= MaxFindings || len(findings) >= MaxFindings {
						outcome.limited = true
						outcome.Status, outcome.Reason = Unknown, "Python conflict evaluation limit reached; remaining metadata was not compared"
						return outcome, findings
					}
					comparisons++
					differs, valid := pythonVersionsDiffer(orphan.Version, other.Version)
					if !valid {
						outcome.Status, outcome.Reason = Unknown, "Python versions could not be compared"
					} else if differs {
						findings = append(findings, shadowFinding(target, opts, rule, []string{orphan.Path, other.Path}, fmt.Sprintf("Unowned Python distribution metadata for %s version %s coexists with conda-owned distribution metadata version %s.", orphan.Name, orphan.Version, other.Version)))
					}
				}
				continue
			}
			if len(byPythonName[name]) == 0 {
				continue
			}
			outcome.Status, outcome.Reason = Unknown, "name-only conda/PyPI correspondence is a candidate, not a verified distribution mapping"
		}
	}
	return outcome, findings
}

func toolingExtras(prefix evidence.Prefix) ([]inventory.CondaRecord, bool, bool) {
	records := map[string]inventory.CondaRecord{}
	var queue []string
	for _, record := range prefix.Records {
		name, valid := canonicalCondaName(record.Record.Name)
		if !valid {
			return nil, false, false
		}
		if _, duplicate := records[name]; duplicate {
			return nil, false, false
		}
		records[name] = record
		if name == "conda" || name == "mamba" || name == "micromamba" {
			queue = append(queue, name)
		}
	}
	if len(queue) == 0 {
		return nil, false, true
	}
	closure := map[string]bool{}
	for len(queue) > 0 {
		name := queue[0]
		queue = queue[1:]
		if closure[name] {
			continue
		}
		closure[name] = true
		for _, dependency := range records[name].Record.Depends {
			parsed, err := gorattler.ParseMatchSpec(dependency)
			if err != nil || parsed.Name == "" {
				return nil, true, false
			}
			// Virtual packages are solver facts, not missing installed records.
			if strings.HasPrefix(parsed.Name, "__") {
				continue
			}
			if _, present := records[parsed.Name]; !present {
				return nil, true, false
			}
			queue = append(queue, parsed.Name)
		}
	}
	var extras []inventory.CondaRecord
	for name, record := range records {
		if !closure[name] {
			extras = append(extras, record)
		}
	}
	slices.SortFunc(extras, func(a, b inventory.CondaRecord) int { return strings.Compare(a.Path, b.Path) })
	return extras, true, true
}

func checkWorkingBase(target evidence.Target, opts RuleOptions, rule Rule) (Outcome, []Finding) {
	outcome := localRecordOutcome(target)
	if outcome.Status == NotApplicable {
		return outcome, nil
	}
	var findings []Finding
	candidates := 0
	for _, prefix := range sortedLocalPrefixes(target) {
		extras, tooling, valid := toolingExtras(prefix)
		if !valid || prefix.RecordCoverage != evidence.Complete {
			outcome.Status, outcome.Reason = Unknown, "tooling dependency closure could not be established for "+prefix.Path+"; records, dependency names or nonvirtual dependencies are missing"
			continue
		}
		if !tooling {
			continue
		}
		candidates++
		if len(extras) == 0 {
			continue
		}
		paths := []string{prefix.Path}
		for _, record := range extras {
			paths = append(paths, record.Path)
		}
		f := newFinding(target, rule, opts.Severity, paths, nil)
		f.Evidence.Count = len(extras)
		f.Message = fmt.Sprintf("The tooling/base candidate at `%s` contains %d packages not required by its installed conda, mamba or micromamba tools, recorded at %s. %s", prefix.Path, len(extras), quotedPaths(f.Evidence.Paths), rule.Description)
		findings = append(findings, f)
	}
	if outcome.Status == Pass {
		if candidates == 0 {
			outcome.Status, outcome.Reason = NotApplicable, "no conda, mamba or micromamba tooling/base candidate was observed"
		} else {
			outcome.Reason = "tooling/base candidate records stay within the installer dependency closure; base identity and runtime use are not established"
		}
	}
	return outcome, findings
}

// CanonicalChannel redacts secrets. Remove only the record's explicit subdir,
// not an arbitrary suffix that happens to resemble a known channel name.
func localChannel(record gorattler.PrefixRecord) (string, bool) {
	channel, err := gorattler.CanonicalChannel(record.Channel)
	if err != nil {
		return "", false
	}
	u, err := url.Parse(channel)
	if err != nil {
		return "", false
	}
	if record.Subdir != "" {
		u.Path = strings.TrimSuffix(strings.TrimSuffix(u.Path, "/"), "/"+record.Subdir)
	}
	u.Path = strings.TrimSuffix(u.Path, "/") + "/"
	return u.String(), true
}

func checkMixedChannels(target evidence.Target, opts RuleOptions, rule Rule) (Outcome, []Finding) {
	outcome := localRecordOutcome(target)
	if outcome.Status == NotApplicable {
		return outcome, nil
	}
	var findings []Finding
	for _, prefix := range sortedLocalPrefixes(target) {
		var defaults, forge []string
		for _, located := range prefix.Records {
			channel, valid := localChannel(located.Record)
			if !valid {
				outcome.Status, outcome.Reason = Unknown, "a channel is unavailable or cannot be canonicalized; custom aliases and the defaults multichannel are not expanded"
				continue
			}
			u, _ := url.Parse(channel)
			switch {
			case strings.EqualFold(u.Host, "repo.anaconda.com") && (u.Path == "/pkgs/main/" || u.Path == "/pkgs/r/" || u.Path == "/pkgs/msys2/"):
				defaults = append(defaults, located.Path)
			case strings.EqualFold(u.Host, "conda.anaconda.org") && u.Path == "/conda-forge/":
				forge = append(forge, located.Path)
			}
		}
		if len(defaults) == 0 || len(forge) == 0 {
			continue
		}
		paths := append([]string{prefix.Path}, defaults...)
		paths = append(paths, forge...)
		f := newFinding(target, rule, opts.Severity, paths, nil)
		f.Evidence.Count = len(defaults) + len(forge)
		f.Message = fmt.Sprintf("The prefix `%s` contains %d packages from the official defaults channels (main, r or msys2) and %d from conda-forge, recorded at %s. %s", prefix.Path, len(defaults), len(forge), quotedPaths(f.Evidence.Paths), rule.Description)
		findings = append(findings, f)
	}
	return outcome, findings
}

func checkHostCache(target evidence.Target, opts RuleOptions, rule Rule) (Outcome, []Finding) {
	outcome := Outcome{Status: Pass, SubjectCount: 1}
	if !completeOf(target, "host-cache") {
		outcome.Status, outcome.Reason = Unknown, "host package-cache coverage is incomplete"
	}
	artifacts := append(slices.Clone(target.Archives), target.Extracted...)
	for i := len(target.Archives); i < len(artifacts); i++ {
		artifacts[i].Bytes = 0 // Extracted payloads are not traversed by host lint.
	}
	if len(artifacts) == 0 {
		if len(target.Prefixes) == 0 && outcome.Status == Pass && completeOf(target, "prefixes") {
			outcome.Status, outcome.Reason = NotApplicable, "no conda environment or record-derived cache was found"
		}
		return outcome, nil
	}
	f := newFinding(target, rule, opts.Severity, nil, artifacts)
	f.Evidence.ByteUnit = "archive file payload bytes; not unique or reclaimable; extracted directory sizes are not measured"
	f.Message = fmt.Sprintf("Host package-cache entries at %s include %d archives (%d file payload bytes) and %d extracted package directories whose sizes were not measured. %s", quotedPaths(f.Evidence.Paths), len(target.Archives), f.Evidence.PayloadBytes, len(target.Extracted), rule.Description)
	return outcome, []Finding{f}
}

// Official CPython status table, verified 2026-10-26:
// https://devguide.python.org/versions/ . Future EOL dates are month-only
// schedules: after their first day, require refreshed data rather than assert EOL.
var pythonSupport = []struct {
	branch, until string
	ended         bool
}{
	{"2.6", "2013-10-29", true}, {"2.7", "2020-01-01", true},
	{"3.0", "2009-06-27", true}, {"3.1", "2012-04-09", true},
	{"3.2", "2016-02-20", true}, {"3.3", "2017-09-29", true},
	{"3.4", "2019-03-18", true}, {"3.5", "2020-09-30", true},
	{"3.6", "2021-12-23", true}, {"3.7", "2023-06-27", true},
	{"3.8", "2024-10-07", true}, {"3.9", "2025-10-31", true},
	{"3.10", "2026-10-01", true}, {"3.11", "2027-10-01", false},
	{"3.12", "2028-10-01", false}, {"3.13", "2029-10-01", false},
	{"3.14", "2030-10-01", false}, {"3.15", "2031-10-01", false},
}

func pythonSupportStatus(version string, asOf time.Time) (branch, date string, ended, known bool) {
	for _, support := range pythonSupport {
		contains, err := gorattler.VersionSpecContains(support.branch+".*", version)
		if err != nil {
			return "", "", false, false
		}
		if !contains {
			continue
		}
		until, _ := time.Parse(time.DateOnly, support.until)
		if !asOf.UTC().Before(until) {
			return support.branch, support.until, support.ended, support.ended
		}
		return support.branch, support.until, false, true
	}
	return "", "", false, false
}

func checkPythonEOL(target evidence.Target, opts RuleOptions, rule Rule) (Outcome, []Finding) {
	outcome := localRecordOutcome(target)
	if outcome.Status == NotApplicable {
		return outcome, nil
	}
	if target.AsOf.IsZero() {
		outcome.Status, outcome.Reason = Unknown, "an explicit evaluation date is required for Python support status"
		return outcome, nil
	}
	var findings []Finding
	pythonCount := 0
	for _, prefix := range sortedLocalPrefixes(target) {
		for _, located := range prefix.Records {
			name, valid := canonicalCondaName(located.Record.Name)
			if !valid {
				outcome.Status, outcome.Reason = Unknown, "a conda package name could not be parsed"
				continue
			}
			if name != "python" {
				continue
			}
			pythonCount++
			branch, date, ended, known := pythonSupportStatus(located.Record.Version, target.AsOf)
			if !known {
				outcome.Status, outcome.Reason = Unknown, "Python version is invalid, unlisted or beyond a scheduled support date; refresh the official status table"
				continue
			}
			if !ended {
				continue
			}
			f := newFinding(target, rule, opts.Severity, []string{prefix.Path, located.Path}, nil)
			f.Evidence.Count = 1
			f.Message = fmt.Sprintf("Python %s in `%s`, recorded at `%s`, belongs to branch %s whose upstream CPython support ended %s (evaluated %s). %s", located.Record.Version, prefix.Path, located.Path, branch, date, target.AsOf.UTC().Format(time.DateOnly), rule.Description)
			findings = append(findings, f)
		}
	}
	if pythonCount == 0 && outcome.Status == Pass {
		outcome.Status, outcome.Reason = NotApplicable, "no installed conda Python package was observed"
	}
	return outcome, findings
}

func checkInstalledLock(target evidence.Target, opts RuleOptions, rule Rule) (Outcome, []Finding) {
	outcome := Outcome{Status: Pass, SubjectCount: 1}
	selection := target.Lock
	if selection == nil {
		if completeOf(target, "installed-lock") {
			outcome.Status, outcome.Reason = NotApplicable, "no installed Pixi lock association was selected"
		} else {
			outcome.Status, outcome.Reason = Unknown, "installed lock selection was not completely inspected"
		}
		return outcome, nil
	}
	if selection.Report == nil || selection.Report.Scope != "conda" {
		outcome.Status, outcome.Reason = Unknown, "no usable conda-only installed metadata comparison is available"
		return outcome, nil
	}
	report := selection.Report
	if !report.Complete || len(report.Unknown) > 0 || !completeOf(target, "installed-lock") {
		outcome.Status, outcome.Reason = Unknown, "installed conda metadata comparison has incomplete evidence or unresolved identities"
	}
	count := len(report.Missing) + len(report.Extra) + len(report.Changed)
	if count == 0 {
		if outcome.Status == Pass && report.Matches {
			outcome.Reason = "installed conda package metadata matches the selected lock; Python distributions, files and manifest synchronization were not verified"
		} else {
			outcome.Status, outcome.Reason = Unknown, "the comparison did not establish a conda metadata match or report concrete differences"
		}
		return outcome, nil
	}
	f := newFinding(target, rule, opts.Severity, []string{selection.Prefix, selection.Path}, nil)
	f.Evidence.Count = count
	var changes []string
	for _, change := range report.Changed {
		changes = append(changes, fmt.Sprintf("%s: locked %s, installed %s", change.Locked.Name, change.Locked.Version, change.Installed.Version))
	}
	slices.Sort(changes)
	f.Evidence.Notes = sampleStrings(changes)
	if len(report.Unknown) > 0 {
		f.Evidence.Notes = append(f.Evidence.Notes[:min(len(f.Evidence.Notes), MaxSamples-1)], "Other identities remain unresolved; the comparison is not a complete all-clear.")
	}
	f.Message = fmt.Sprintf("Installed conda package metadata in `%s` differs from `%s` (environment %s, subdir %s): %d missing, %d extra, %d changed. %s", selection.Prefix, selection.Path, selection.Environment, selection.Subdir, len(report.Missing), len(report.Extra), len(report.Changed), rule.Description)
	if runtime.GOOS != "windows" {
		f.Next = fmt.Sprintf("In a POSIX shell in `%s`, run `pixi install --environment %s`, then recheck installed conda metadata.", filepath.Dir(selection.Path), commandArg(selection.Environment))
	}
	return outcome, []Finding{f}
}

func checkRequestedSpecs(target evidence.Target, opts RuleOptions, rule Rule) (Outcome, []Finding) {
	outcome := localRecordOutcome(target)
	if outcome.Status == NotApplicable {
		return outcome, nil
	}
	requested := 0
	var findings []Finding
	for _, prefix := range sortedLocalPrefixes(target) {
		var paths []string
		for _, located := range prefix.Records {
			specs := slices.Clone(located.Record.RequestedSpecs)
			if located.Record.RequestedSpec != "" {
				specs = append(specs, located.Record.RequestedSpec)
			}
			name, valid := canonicalCondaName(located.Record.Name)
			unconstrained := false
			for _, spec := range specs {
				requested++
				parsed, err := gorattler.ParseMatchSpec(spec)
				if err != nil || !valid || parsed.Name != name {
					outcome.Status, outcome.Reason = Unknown, "requested specs contain an invalid or mismatched package name"
					continue
				}
				// Pinned also requires an exact build: a range is constrained even
				// though Pinned is false. Only absent or wildcard versions count.
				unconstrained = unconstrained || parsed.Version == "" || parsed.Version == "*"
			}
			if unconstrained {
				paths = append(paths, located.Path)
			}
		}
		if len(paths) == 0 {
			continue
		}
		f := newFinding(target, rule, opts.Severity, append([]string{prefix.Path}, paths...), nil)
		f.Evidence.Count = len(paths)
		f.Message = fmt.Sprintf("The prefix `%s` has %d requested package specs with no version constraint, recorded at %s. %s", prefix.Path, len(paths), quotedPaths(f.Evidence.Paths), rule.Description)
		findings = append(findings, f)
	}
	if requested == 0 && outcome.Status == Pass {
		outcome.Status, outcome.Reason = NotApplicable, "no requested specs were recorded; absent metadata does not establish an unpinned request"
	}
	return outcome, findings
}
