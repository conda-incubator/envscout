package lint

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"slices"
	"strings"

	"github.com/conda-incubator/envscout/internal/evidence"
)

// completeOf reports whether the target completed the named coverage capability.
func completeOf(target evidence.Target, capability string) bool {
	return target.Coverage[capability] == evidence.Complete
}

func checkRevision(target evidence.Target, opts RuleOptions, rule Rule) (Outcome, []Finding) {
	outcome := Outcome{Status: Pass}
	var findings []Finding
	outcome.SubjectCount = len(target.Prefixes)
	threshold := defaultRevisionThreshold
	if value := opts.RevisionThreshold; value != nil {
		threshold = *value
	}
	prefixes := slices.Clone(target.Prefixes)
	slices.SortFunc(prefixes, func(a, b evidence.Prefix) int { return strings.Compare(a.Path, b.Path) })
	missing := 0
	for _, prefix := range prefixes {
		if prefix.Revision == nil {
			missing++
			continue
		}
		if *prefix.Revision < threshold {
			continue
		}
		f := newFinding(target, rule, opts.Severity, []string{prefix.Path}, nil)
		revision := *prefix.Revision
		f.Evidence.Revision, f.Evidence.RevisionThreshold = &revision, &threshold
		f.Evidence.Count = 1
		f.Message = fmt.Sprintf("Conda history revision %d meets the configured review threshold %d.", revision, threshold)
		findings = append(findings, f)
	}
	if len(prefixes) == 0 && completeOf(target, "prefixes") {
		outcome.Status, outcome.Reason = NotApplicable, "zero recognized environment subjects in the inspected scope"
	} else if missing > 0 || !completeOf(target, "prefixes") || !completeOf(target, "history") {
		outcome.Status = Unknown
		outcome.Reason = fmt.Sprintf("%d environment subjects have no readable revision; history or prefix coverage may be incomplete", missing)
	}
	return outcome, findings
}

func checkProjectLock(target evidence.Target, opts RuleOptions, rule Rule) (Outcome, []Finding) {
	outcome := Outcome{Status: Pass}
	var findings []Finding
	outcome.SubjectCount = 1
	project := target.Project
	switch {
	case project == nil || !project.Associated:
		outcome.Status, outcome.Reason = Unknown, "no verified explicit project association; nearby lockfiles are not mapped to this environment"
	case !completeOf(target, "project-association"):
		outcome.Status, outcome.Reason = Unknown, "associated project scope was not completely inspected"
	case project.LockVerified:
		outcome.Reason = "associated project has a verified resolved lock"
	case project.LockPath != "":
		outcome.Status, outcome.Reason = Unknown, "associated project has a lock whose resolution could not be verified"
	default:
		f := newFinding(target, rule, opts.Severity, []string{project.Path}, nil)
		copied := *project
		f.Evidence.Project = &copied
		f.Evidence.Count = 1
		f.Message = "The explicitly associated local project has no verified resolved lock in its inspected project scope."
		findings = append(findings, f)
	}
	return outcome, findings
}

// artifactRule describes one artifact-based rule. It is data, not a rule ID branch.
type artifactRule struct {
	selector      func(evidence.Target) []evidence.Artifact
	capability    string
	byteUnit      string
	message       string
	notes         []string
	absenceReason string
}

func archivesOf(t evidence.Target) []evidence.Artifact { return t.Archives }
func retainedOf(t evidence.Target) []evidence.Artifact { return t.Retained }
func toolsOf(t evidence.Target) []evidence.Artifact    { return t.Tools }
func shellsOf(t evidence.Target) []evidence.Artifact   { return t.Shells }

// artifactCheck builds a Check for artifact-group rules. Message, notes and the
// absence reason are rule data; the finding shape is identical to prior output.
func artifactCheck(spec artifactRule) func(evidence.Target, RuleOptions, Rule) (Outcome, []Finding) {
	return func(target evidence.Target, opts RuleOptions, rule Rule) (Outcome, []Finding) {
		outcome := Outcome{Status: Pass}
		outcome.SubjectCount = 1
		artifacts := spec.selector(target)
		if len(artifacts) == 0 {
			if !completeOf(target, spec.capability) {
				outcome.Status, outcome.Reason = Unknown, "required "+spec.capability+" coverage is not complete; absence was not established"
			} else if spec.absenceReason != "" {
				outcome.Reason = spec.absenceReason
			}
			return outcome, nil
		}
		f := newFinding(target, rule, opts.Severity, nil, artifacts)
		if spec.byteUnit != "" {
			f.Evidence.ByteUnit = spec.byteUnit
		}
		f.Message = fmt.Sprintf(spec.message, f.Evidence.Count)
		if spec.notes != nil {
			f.Evidence.Notes = slices.Clone(spec.notes)
		}
		return outcome, []Finding{f}
	}
}

func checkExtractedCache(target evidence.Target, opts RuleOptions, rule Rule) (Outcome, []Finding) {
	outcome := Outcome{Status: Pass}
	outcome.SubjectCount = 1
	if len(target.Extracted) == 0 {
		if !completeOf(target, "final-cache") {
			outcome.Status, outcome.Reason = Unknown, "required final-cache coverage is not complete; absence was not established"
		}
		return outcome, nil
	}
	severity := opts.Severity
	if !completeOf(target, "cache-link-dependencies") || target.CacheLinked {
		severity = Info
	}
	f := newFinding(target, rule, severity, nil, target.Extracted)
	f.Evidence.CacheLinked = target.CacheLinked
	f.Evidence.LinkCoverage = target.Coverage["cache-link-dependencies"]
	if f.Evidence.LinkCoverage == "" {
		f.Evidence.LinkCoverage = evidence.NotCollected
	}
	f.Message = fmt.Sprintf("%d extracted package-cache entries remain in the final image.", f.Evidence.Count)
	switch {
	case target.CacheLinked:
		f.Evidence.Notes = []string{"Surviving runtime references to cache content were observed; cleanup is unsafe without preserving those dependencies."}
	case !completeOf(target, "cache-link-dependencies"):
		f.Evidence.Notes = []string{"Required cache linkage inspection is incomplete; cleanup safety is unknown."}
	default:
		f.Evidence.Notes = []string{"Linkage checks completed without an observed runtime cache dependency; runtime behavior still requires testing."}
	}
	return outcome, []Finding{f}
}

func checkPrefixRoles(target evidence.Target, opts RuleOptions, rule Rule) (Outcome, []Finding) {
	outcome := Outcome{Status: Pass}
	outcome.SubjectCount = 1
	tooling, apps := prefixRoles(target)
	if len(tooling) == 0 || len(apps) == 0 {
		if !completeOf(target, "prefixes") || !completeOf(target, "tooling-prefix") || !completeOf(target, "runtime-config") {
			outcome.Status, outcome.Reason = Unknown, "prefix roles or runtime configuration could not be completely inspected"
		}
		return outcome, nil
	}
	paths := append(slices.Clone(tooling), apps...)
	f := newFinding(target, rule, opts.Severity, paths, nil)
	f.Evidence.ToolingPrefixes = sampleStrings(tooling)
	f.Evidence.AppPrefixes = sampleStrings(apps)
	f.Evidence.RuntimePrefix = target.RuntimePrefix
	f.Evidence.RuntimeUsesTooling = target.RuntimeUsesTooling
	f.Evidence.Count = len(tooling) + len(apps)
	f.Message = "Confirmed tooling prefixes coexist with distinct application-prefix candidates."
	switch {
	case target.RuntimeUsesTooling:
		f.Evidence.Notes = []string{"Configured startup uses tooling; this evidence does not justify removing the tooling prefix."}
	case target.RuntimePrefix == "":
		f.Evidence.Notes = []string{"Application role is a recognized nested-layout candidate; runtime attribution is not verified."}
	default:
		f.Evidence.Notes = []string{"Runtime prefix is an asserted or supported configuration input, not proof of exclusive execution."}
	}
	return outcome, []Finding{f}
}

func prefixRoles(target evidence.Target) ([]string, []string) {
	tooling := []string{}
	apps := []string{}
	for _, prefix := range target.Prefixes {
		if prefix.Tooling {
			tooling = append(tooling, prefix.Path)
		}
	}
	for _, prefix := range target.Prefixes {
		if prefix.Tooling {
			continue
		}
		candidate := target.RuntimePrefix != "" && prefix.Path == target.RuntimePrefix
		for _, root := range tooling {
			candidate = candidate || strings.HasPrefix(prefix.Path, strings.TrimSuffix(root, "/")+"/envs/")
		}
		if candidate {
			apps = append(apps, prefix.Path)
		}
	}
	slices.Sort(tooling)
	slices.Sort(apps)
	return slices.Compact(tooling), slices.Compact(apps)
}

// newFinding builds the per-instance finding. Rule metadata (confidence,
// recommendation, references, category, version) is read from LookupRule.
func newFinding(target evidence.Target, rule Rule, severity Severity, paths []string, artifacts []evidence.Artifact) Finding {
	all := slices.Clone(artifacts)
	slices.SortFunc(all, compareArtifacts)
	all = slices.Compact(all)
	paths = slices.Clone(paths)
	references := []string{}
	var bytes int64
	for _, artifact := range all {
		paths = append(paths, artifact.Path)
		references = append(references, fmt.Sprintf("%s\x00%s\x00%s\x00%s\x00%d", artifact.Path, artifact.Reference, artifact.DiffID, artifact.BlobDigest, artifact.Layer))
		if artifact.Bytes > 0 {
			if bytes > math.MaxInt64-artifact.Bytes {
				bytes = math.MaxInt64
			} else {
				bytes += artifact.Bytes
			}
		}
	}
	slices.Sort(paths)
	paths = slices.Compact(paths)
	slices.Sort(references)
	references = slices.Compact(references)
	identity, _ := json.Marshal(struct {
		Rule       string   `json:"rule"`
		Target     string   `json:"target"`
		Paths      []string `json:"paths"`
		References []string `json:"references"`
	}{rule.ID, target.ID, paths, references})
	digest := sha256.Sum256(identity)
	f := Finding{RuleID: rule.ID, Target: target.ID, Severity: severity,
		Fingerprint: hex.EncodeToString(digest[:]), paths: paths,
		Evidence: FindingEvidence{Paths: sampleStrings(paths), Locations: []string{}, Samples: []evidence.Artifact{}, Count: len(all), PayloadBytes: bytes}}
	for _, p := range f.Evidence.Paths {
		f.Evidence.Locations = append(f.Evidence.Locations, location(target, p))
	}
	if len(all) > 0 {
		f.Evidence.Samples = slices.Clone(all[:min(len(all), MaxSamples)])
		f.Evidence.ByteUnit = "logical payload bytes; not unique or reclaimable bytes"
	}
	return f
}

// compareArtifacts orders artifacts by identity fields, then payload sizes.
func compareArtifacts(a, b evidence.Artifact) int {
	return cmp.Or(cmp.Compare(a.Path, b.Path), cmp.Compare(a.Reference, b.Reference),
		cmp.Compare(a.DiffID, b.DiffID), cmp.Compare(a.BlobDigest, b.BlobDigest),
		cmp.Compare(a.Layer, b.Layer), cmp.Compare(a.Kind, b.Kind),
		cmp.Compare(a.Bytes, b.Bytes), cmp.Compare(a.LayerBytes, b.LayerBytes))
}

func sampleStrings(values []string) []string {
	if len(values) == 0 {
		return []string{}
	}
	return slices.Clone(values[:min(len(values), MaxSamples)])
}
