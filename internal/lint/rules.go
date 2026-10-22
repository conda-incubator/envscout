package lint

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"slices"
	"strings"

	"github.com/anaconda/envscout/internal/evidence"
)

func evaluateRule(target evidence.Target, policy Policy, rule Rule) (Outcome, []Finding) {
	outcome := Outcome{RuleID: rule.ID, RuleVersion: rule.Version, Target: target.ID, Status: Pass, Findings: []string{}}
	if !ruleEnabled(policy, rule.ID) {
		outcome.Status = Disabled
		return outcome, nil
	}
	if !rule.Available {
		outcome.Status, outcome.Reason = Unavailable, rule.UnavailableReason
		return outcome, nil
	}
	if !slices.Contains(rule.TargetKinds, target.Kind) {
		outcome.Status, outcome.Reason = NotApplicable, "rule does not apply to this source kind"
		return outcome, nil
	}
	severity := policy.Rules[rule.ID].Severity
	findings := []Finding{}
	unknown := func(reason string) {
		outcome.Status, outcome.Reason = Unknown, reason
	}
	complete := func(capability string) bool { return target.Coverage[capability] == evidence.Complete }
	switch rule.ID {
	case "EC001":
		outcome.SubjectCount = len(target.Prefixes)
		threshold := 10
		if value := policy.Rules[rule.ID].RevisionThreshold; value != nil {
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
			f := newFinding(target, rule, severity, "high", []string{prefix.Path}, nil)
			revision := *prefix.Revision
			f.Evidence.Revision, f.Evidence.RevisionThreshold = &revision, &threshold
			f.Evidence.Count = 1
			f.Message = fmt.Sprintf("Conda history revision %d meets the configured review threshold %d.", revision, threshold)
			f.Recommendation = "Review the recorded dependency transactions and, if useful, recreate from recorded dependencies. Revision is a transaction count, not evidence of drift, corruption, age or vulnerabilities; it does not account for pip installs or arbitrary file edits."
			findings = append(findings, f)
		}
		if len(prefixes) == 0 && complete("prefixes") {
			outcome.Status, outcome.Reason = NotApplicable, "zero recognized environment subjects in the inspected scope"
		} else if missing > 0 || !complete("prefixes") || !complete("history") {
			unknown(fmt.Sprintf("%d environment subjects have no readable revision; history or prefix coverage may be incomplete", missing))
		}
	case "EC004":
		outcome.SubjectCount = 1
		project := target.Project
		if project == nil || !project.Associated {
			unknown("no verified explicit project association; nearby lockfiles are not mapped to this environment")
		} else if !complete("project-association") {
			unknown("associated project scope was not completely inspected")
		} else if project.LockVerified {
			outcome.Reason = "associated project has a verified resolved lock"
		} else if project.LockPath != "" {
			unknown("associated project has a lock whose resolution could not be verified")
		} else {
			f := newFinding(target, rule, severity, "high", []string{project.Path}, nil)
			copy := *project
			f.Evidence.Project = &copy
			f.Evidence.Count = 1
			f.Message = "The explicitly associated local project has no verified resolved lock in its inspected project scope."
			f.Recommendation = "Review the project's portability and reproducibility requirements and record a supported resolved lock when appropriate. This observation is not an installed-package mismatch and does not require a lock in a runtime image."
			findings = append(findings, f)
		}
	case "IC001", "IC002", "IC004", "IC006", "IC007":
		var artifacts []evidence.Artifact
		capability := "final-cache"
		switch rule.ID {
		case "IC001":
			artifacts = target.Archives
		case "IC002":
			artifacts = target.Extracted
		case "IC004":
			artifacts, capability = target.Retained, "layer-retention"
		case "IC006":
			artifacts, capability = target.Tools, "os-package-tools"
		case "IC007":
			artifacts, capability = target.Shells, "shell-tools"
		}
		outcome.SubjectCount = 1
		if len(artifacts) == 0 {
			if !complete(capability) {
				unknown("required " + capability + " coverage is not complete; absence was not established")
			} else if rule.ID == "IC006" || rule.ID == "IC007" {
				outcome.Reason = "no confirmed commands at recognized inspected locations; custom installation paths are outside this predicate"
			}
			break
		}
		if rule.ID == "IC002" && (!complete("cache-link-dependencies") || target.CacheLinked) {
			severity = "info"
		}
		f := newFinding(target, rule, severity, "high", nil, artifacts)
		if rule.ID == "IC004" {
			// Logical retained payload is evidence only. Whole compressed layer
			// sizes stay on samples and must never be summed into savings.
			f.Evidence.ByteUnit = "retained logical payload bytes; not compressed or reclaimable bytes"
		}
		switch rule.ID {
		case "IC001":
			f.Message = fmt.Sprintf("%d download archives remain in confirmed final-image conda package caches.", f.Evidence.Count)
			f.Recommendation = "Review build-time download-archive cleanup using the package manager's tarball-only cleanup or a BuildKit cache mount. Observed archive payload bytes are not predicted image-size or vulnerability savings."
		case "IC002":
			f.Evidence.CacheLinked = target.CacheLinked
			f.Evidence.LinkCoverage = target.Coverage["cache-link-dependencies"]
			if f.Evidence.LinkCoverage == "" {
				f.Evidence.LinkCoverage = evidence.NotCollected
			}
			f.Message = fmt.Sprintf("%d extracted package-cache entries remain in the final image.", f.Evidence.Count)
			f.Recommendation = "Prefer copying a tested application prefix into a compatible runtime stage. Extracted caches can supply required symlink or hardlink targets; do not remove them without validating dependency and relocation behavior. Logical payload bytes are not unique or reclaimable bytes."
			if target.CacheLinked {
				f.Evidence.Notes = []string{"Surviving runtime references to cache content were observed; cleanup is unsafe without preserving those dependencies."}
			} else if !complete("cache-link-dependencies") {
				f.Evidence.Notes = []string{"Required cache linkage inspection is incomplete; cleanup safety is unknown."}
			} else {
				f.Evidence.Notes = []string{"Linkage checks completed without an observed runtime cache dependency; runtime behavior still requires testing."}
			}
		case "IC004":
			f.Message = fmt.Sprintf("%d hidden or replaced cache references remain in final-image referenced layers.", f.Evidence.Count)
			f.Recommendation = "Review same-step build-time cleanup, BuildKit cache mounts, or a dedicated compatible runtime stage. A later deletion does not remove earlier referenced layer content. Compressed descriptor sizes describe complete layers, not per-file savings; this evidence does not identify Dockerfile instructions or unrelated builder stages."
		case "IC006":
			f.Message = fmt.Sprintf("%d OS package-manager command identities are confirmed in the final image.", f.Evidence.Count)
			f.Recommendation = "For declared runtime images, review keeping installation commands in the builder stage and copying tested runtime contents into a compatible final image. Intentional package-management workloads may retain them. Preserve package databases, conda metadata and shared runtime libraries for behavior and scanner visibility; removing evidence is not vulnerability remediation."
			f.Evidence.Notes = []string{"Recognition covers typed known command locations, not every possible custom installation path."}
		case "IC007":
			f.Message = fmt.Sprintf("%d shell command identities are confirmed under the selected shell policy.", f.Evidence.Count)
			f.Recommendation = "Review intentional debug and shell-dependent startup exceptions. Validate exec-form startup, activation and runtime behavior before changing to a shell-free compatible runtime base; shell presence alone is not a vulnerability finding."
			f.Evidence.Notes = []string{"Recognition covers typed known command locations, including resolved aliases, not every custom installation path."}
		}
		findings = append(findings, f)
	case "IC003":
		outcome.SubjectCount = 1
		tooling, apps := prefixRoles(target)
		if len(tooling) > 0 && len(apps) > 0 {
			paths := append(slices.Clone(tooling), apps...)
			f := newFinding(target, rule, severity, "medium", paths, nil)
			f.Evidence.ToolingPrefixes = sampleStrings(tooling)
			f.Evidence.AppPrefixes = sampleStrings(apps)
			f.Evidence.RuntimePrefix = target.RuntimePrefix
			f.Evidence.RuntimeUsesTooling = target.RuntimeUsesTooling
			f.Evidence.Count = len(tooling) + len(apps)
			f.Message = "Confirmed tooling prefixes coexist with distinct application-prefix candidates."
			f.Recommendation = "Review the separate tooling and application roles before considering a compatible runtime-stage copy. Configuration hints do not prove that a prefix is unused; an application running in base is valid. Preserve required activation, runtime libraries and relocation behavior."
			if target.RuntimeUsesTooling {
				f.Evidence.Notes = []string{"Configured startup uses tooling; this evidence does not justify removing the tooling prefix."}
			} else if target.RuntimePrefix == "" {
				f.Evidence.Notes = []string{"Application role is a recognized nested-layout candidate; runtime attribution is not verified."}
			} else {
				f.Evidence.Notes = []string{"Runtime prefix is an asserted or supported configuration input, not proof of exclusive execution."}
			}
			findings = append(findings, f)
		} else if !complete("prefixes") || !complete("tooling-prefix") || !complete("runtime-config") {
			unknown("prefix roles or runtime configuration could not be completely inspected")
		}
	}
	if len(findings) > 0 {
		outcome.Status = FindingStatus
		for _, f := range findings {
			outcome.Findings = append(outcome.Findings, f.Fingerprint)
		}
	}
	return outcome, findings
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

func newFinding(target evidence.Target, rule Rule, severity, confidence string, paths []string, artifacts []evidence.Artifact) Finding {
	all := slices.Clone(artifacts)
	slices.SortFunc(all, func(a, b evidence.Artifact) int {
		if n := strings.Compare(a.Path, b.Path); n != 0 {
			return n
		}
		if n := strings.Compare(a.Reference, b.Reference); n != 0 {
			return n
		}
		if n := strings.Compare(a.DiffID, b.DiffID); n != 0 {
			return n
		}
		if n := strings.Compare(a.BlobDigest, b.BlobDigest); n != 0 {
			return n
		}
		if n := a.Layer - b.Layer; n != 0 {
			return n
		}
		if n := strings.Compare(a.Kind, b.Kind); n != 0 {
			return n
		}
		if a.Bytes < b.Bytes {
			return -1
		}
		if a.Bytes > b.Bytes {
			return 1
		}
		if a.LayerBytes < b.LayerBytes {
			return -1
		}
		if a.LayerBytes > b.LayerBytes {
			return 1
		}
		return 0
	})
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
	f := Finding{RuleID: rule.ID, RuleVersion: rule.Version, Target: target.ID, Severity: severity,
		Confidence: confidence, Category: rule.Category, References: slices.Clone(rule.References),
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

func sampleStrings(values []string) []string {
	if len(values) == 0 {
		return []string{}
	}
	return slices.Clone(values[:min(len(values), MaxSamples)])
}
