package lint

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"path"
	"runtime"
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
		f.Message = fmt.Sprintf("%s has %d recorded conda transactions (revision %d; review threshold %d). Repeated changes make the original dependency choices harder to review.", quotedPaths([]string{prefix.Path}), uint64(revision)+1, revision, threshold)
		if runtime.GOOS != "windows" {
			f.Next = fmt.Sprintf("In a POSIX shell, export with `conda env export --prefix %s --from-history`, review the requested dependencies, and recreate in a new prefix.", commandArg(prefix.Path))
		}
		if target.Kind == "oci-archive" {
			f.Next = "In the matching image or its build environment, " + rule.Fix
		}
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
		outcome.Status, outcome.Reason = NotApplicable, "no explicit --project association"
	case !completeOf(target, "project-association"):
		outcome.Status, outcome.Reason = Unknown, "associated project scope was not completely inspected"
	case project.LockPath != "":
		outcome.Reason = "recognized lockfile is present; installation synchronization is outside this check"
	default:
		f := newFinding(target, rule, opts.Severity, []string{project.Path}, nil)
		copied := *project
		f.Evidence.Project = &copied
		f.Evidence.Count = 1
		f.Message = fmt.Sprintf("No pixi.lock, conda-lock.yml, conda-lock.yaml, uv.lock, poetry.lock or Pipfile.lock was found in project root %s. A resolved lock records dependency choices that a manifest alone leaves open.", quotedPaths([]string{project.Path}))
		f.Next = fmt.Sprintf("In %s, run `pixi lock`, `conda-lock lock`, or the locking command for the project's package manager.", quotedPaths([]string{project.Path}))
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
		f.Message = fmt.Sprintf(spec.message, f.Evidence.Count) + " at " + quotedPaths(f.Evidence.Paths) + ". " + rule.Description
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
	f.Message = fmt.Sprintf("%d extracted package-cache entries remain at %s. Installation content can add files the application does not need.", f.Evidence.Count, quotedPaths(f.Evidence.Paths))
	switch {
	case target.CacheLinked:
		f.Evidence.Notes = []string{"Runtime references to cache content were observed. Preserve those dependencies before removing cache paths."}
	case !completeOf(target, "cache-link-dependencies"):
		f.Evidence.Notes = []string{"Cache linkage inspection is incomplete. Do not assume these paths are safe to remove."}
	default:
		f.Evidence.Notes = []string{"No runtime cache reference was observed. Review unused entries with the package manager and test the resulting image."}
	}
	return outcome, []Finding{f}
}

func checkPrefixRoles(target evidence.Target, opts RuleOptions, rule Rule) (Outcome, []Finding) {
	outcome := Outcome{Status: Pass}
	outcome.SubjectCount = 1
	tooling, apps := prefixRoles(target)
	if target.RuntimeUsesTooling || slices.Contains(tooling, target.RuntimePrefix) {
		outcome.Reason = "configured startup uses the tooling prefix"
		if !completeOf(target, "prefixes") || !completeOf(target, "tooling-prefix") || !completeOf(target, "runtime-config") {
			outcome.Status, outcome.Reason = Unknown, "prefix roles or runtime configuration inspection is incomplete"
		}
		return outcome, nil
	}
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
	f.Message = fmt.Sprintf("Installer prefixes %s coexist with application-prefix candidates %s. A separate installer can add build tooling to the application image.", quotedPaths(tooling), quotedPaths(apps))
	switch target.RuntimePrefix {
	case "":
		f.Evidence.Notes = []string{"The application candidate comes from its nested envs/ path. Startup may use a wrapper; verify which prefix it needs before changing the image."}
	default:
		f.Evidence.Notes = []string{"Startup identifies or asserts the application prefix. Check activation and runtime dependencies before removing installer content."}
	}
	return outcome, []Finding{f}
}

// quotedPaths bounds user-facing path lists in the same way as finding evidence.
func quotedPaths(paths []string) string {
	shown := sampleStrings(paths)
	for i, p := range shown {
		shown[i] = "`" + p + "`"
	}
	text := strings.Join(shown, ", ")
	if len(paths) > len(shown) {
		text += fmt.Sprintf(" (and %d more)", len(paths)-len(shown))
	}
	return text
}

// commandArg quotes a path or selector as a single POSIX-shell argument.
func commandArg(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
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
	if target.Kind == "oci-archive" {
		for i, p := range f.Evidence.Paths {
			f.Evidence.Paths[i] = path.Join("/", p)
		}
	}
	for _, p := range f.Evidence.Paths {
		f.Evidence.Locations = append(f.Evidence.Locations, location(target, p))
	}
	if len(all) > 0 {
		f.Evidence.Samples = slices.Clone(all[:min(len(all), MaxSamples)])
		f.Evidence.ByteUnit = "file payload bytes; not unique or reclaimable bytes"
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
