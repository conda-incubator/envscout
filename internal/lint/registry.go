package lint

import "slices"

var profiles = []string{"local", "container", "container-runtime", "container-distroless", "container-development"}

const (
	condaCleanReference      = "https://docs.conda.io/projects/conda/en/stable/commands/clean.html"
	dockerStageReference     = "https://docs.docker.com/build/building/multi-stage/"
	dockerCacheReference     = "https://docs.docker.com/build/cache/optimize/"
	distrolessReference      = "https://github.com/GoogleContainerTools/distroless"
	metadataReference        = "https://github.com/GoogleContainerTools/distroless/blob/main/PACKAGE_METADATA.md"
	defaultRevisionThreshold = 10
)

// profileDefaults returns the complete per-profile default map. Profiles absent
// from enabled are disabled. Severity defaults to Info unless overridden, and
// threshold is attached to every profile when non-nil.
func profileDefaults(enabled []string, severityFor map[string]Severity, threshold *int) map[string]RuleDefault {
	defaults := make(map[string]RuleDefault, len(profiles))
	for _, profile := range profiles {
		severity := severityFor[profile]
		if severity == "" {
			severity = Info
		}
		defaults[profile] = RuleDefault{Enabled: slices.Contains(enabled, profile), Severity: severity, RevisionThreshold: threshold}
	}
	return defaults
}

var (
	localOnly      = []string{"local"}
	nonLocal       = []string{"container", "container-runtime", "container-distroless", "container-development"}
	runtimeOnly    = []string{"container-runtime", "container-distroless"}
	distrolessOnly = []string{"container-distroless"}
	allWarning     = map[string]Severity{"local": Warning, "container": Warning, "container-runtime": Warning, "container-distroless": Warning, "container-development": Warning}
)

// registry is the single source of rule identity, metadata, defaults and
// evaluation. Its IDs are the only rule identity list.
var registry = []Rule{
	{
		ID: "EC001", Version: "1", Name: "History revision review", Category: "history",
		Description: "Readable conda history revision meets the configured transaction-count threshold.",
		TargetKinds: []string{"dir", "oci-archive"}, Capabilities: []string{"prefixes", "history"}, Available: true,
		Confidence: "high", Fix: "Review the recorded dependency transactions and, if useful, recreate from recorded dependencies. Revision is a transaction count, not evidence of drift, corruption, age or vulnerabilities; it does not account for pip installs or arbitrary file edits.",
		References:                []string{"https://docs.conda.io/projects/conda/en/stable/user-guide/tasks/manage-environments.html"},
		Exceptions:                []string{"Revision counts do not measure drift, age, corruption, pip edits or vulnerabilities."},
		Defaults:                  profileDefaults([]string{"local", "container-development"}, nil, new(defaultRevisionThreshold)),
		SupportsRevisionThreshold: true, Check: checkRevision,
	},
	{
		ID: "EC002", Version: "1", Name: "Installed Pixi lock synchronization", Category: "reproducibility",
		Description: "Authoritatively compare the installed Pixi selection with its resolved lock.",
		TargetKinds: []string{"dir"}, Capabilities: []string{"project-association", "installed-lock"},
		UnavailableReason: "This build has no authoritative Pixi installed-lock hash verification API.",
		References:        []string{"https://pixi.sh/latest/workspace/lockfile/"},
		Exceptions:        []string{"Missing markers and unsupported hash algorithms cannot establish a mismatch."},
		Defaults:          profileDefaults(localOnly, allWarning, nil),
	},
	{
		ID: "EC003", Version: "1", Name: "Manifest lock synchronization", Category: "reproducibility",
		Description: "Authoritatively compare a supported manifest with its resolved lock.",
		TargetKinds: []string{"dir"}, Capabilities: []string{"project-association", "manifest-lock"},
		UnavailableReason: "This build has no authoritative Pixi manifest-lock comparison API.",
		References:        []string{"https://pixi.sh/latest/workspace/lockfile/"},
		Exceptions:        []string{"Timestamps and package counts do not establish stale resolution."},
		Defaults:          profileDefaults(localOnly, allWarning, nil),
	},
	{
		ID: "EC004", Version: "1", Name: "Associated project lock review", Category: "reproducibility",
		Description: "An explicitly associated local project has no verified resolved lock in its inspected scope.",
		TargetKinds: []string{"dir"}, Capabilities: []string{"project-association"}, Available: true,
		Confidence: "high", Fix: "Review the project's portability and reproducibility requirements and record a supported resolved lock when appropriate. This observation is not an installed-package mismatch and does not require a lock in a runtime image.",
		References: []string{"https://pixi.sh/latest/workspace/lockfile/"},
		Exceptions: []string{"Unassociated prefixes and absent runtime-image lockfiles are not violations.", "An unverified existing lock is unknown, not an absent lock."},
		Defaults:   profileDefaults(localOnly, nil, nil), Check: checkProjectLock,
	},
	{
		ID: "IC001", Version: "1", Name: "Final image download archives", Category: "footprint",
		Description: "Download archives remain in a confirmed final-image conda package cache.",
		TargetKinds: []string{"oci-archive"}, Capabilities: []string{"final-cache"}, Available: true,
		Confidence: "high", Fix: "Review build-time download-archive cleanup using the package manager's tarball-only cleanup or a BuildKit cache mount. Observed archive payload bytes are not predicted image-size or vulnerability savings.",
		References: []string{condaCleanReference, dockerCacheReference},
		Exceptions: []string{"Only confirmed cache-context archives count; payload bytes are not predicted savings."},
		Defaults:   profileDefaults(nonLocal, map[string]Severity{"container-runtime": Warning, "container-distroless": Warning}, nil),
		Check:      artifactCheck(artifactRule{selector: archivesOf, capability: "final-cache", message: "%d download archives remain in confirmed final-image conda package caches."}),
	},
	{
		ID: "IC002", Version: "1", Name: "Final image extracted package cache", Category: "footprint",
		Description: "Extracted package entries remain in a confirmed final-image conda package cache.",
		TargetKinds: []string{"oci-archive"}, Capabilities: []string{"final-cache", "cache-link-dependencies"}, Available: true,
		Confidence: "high", Fix: "Prefer copying a tested application prefix into a compatible runtime stage. Extracted caches can supply required symlink or hardlink targets; do not remove them without validating dependency and relocation behavior. Logical payload bytes are not unique or reclaimable bytes.",
		References: []string{condaCleanReference, dockerStageReference},
		Exceptions: []string{"Required cache links or incomplete linkage inspection make cleanup unsafe or unknown.", "Hardlinked logical bytes are not unique or reclaimable bytes."},
		Defaults:   profileDefaults(nonLocal, map[string]Severity{"container-runtime": Warning, "container-distroless": Warning}, nil),
		Check:      checkExtractedCache,
	},
	{
		ID: "IC003", Version: "1", Name: "Tooling and application prefixes", Category: "runtime-layout",
		Description: "A confirmed tooling prefix coexists with a nested or explicitly asserted distinct application prefix.",
		TargetKinds: []string{"oci-archive"}, Capabilities: []string{"prefixes", "tooling-prefix", "runtime-config"}, Available: true,
		Confidence: "medium", Fix: "Review the separate tooling and application roles before considering a compatible runtime-stage copy. Configuration hints do not prove that a prefix is unused; an application running in base is valid. Preserve required activation, runtime libraries and relocation behavior.",
		References: []string{dockerStageReference},
		Exceptions: []string{"Application-in-base images are valid.", "Runtime configuration is supporting evidence, not proof that a prefix is unused."},
		Defaults:   profileDefaults(nonLocal, nil, nil), Check: checkPrefixRoles,
	},
	{
		ID: "IC004", Version: "1", Name: "Retained layer cache content", Category: "footprint",
		Description: "Confirmed hidden or replaced cache references remain in final-image referenced layers.",
		TargetKinds: []string{"oci-archive"}, Capabilities: []string{"layer-retention"}, Available: true,
		Confidence: "high", Fix: "Review same-step build-time cleanup, BuildKit cache mounts, or a dedicated compatible runtime stage. A later deletion does not remove earlier referenced layer content. Compressed descriptor sizes describe complete layers, not per-file savings; this evidence does not identify Dockerfile instructions or unrelated builder stages.",
		References: []string{dockerStageReference, dockerCacheReference},
		Exceptions: []string{"Compressed descriptor bytes describe whole layers, never per-file reclaimable savings.", "Surviving cache hardlinks must not be classified as runtime-unused content."},
		Defaults:   profileDefaults(runtimeOnly, allWarning, nil),
		Check:      artifactCheck(artifactRule{selector: retainedOf, capability: "layer-retention", byteUnit: "retained logical payload bytes; not compressed or reclaimable bytes", message: "%d hidden or replaced cache references remain in final-image referenced layers."}),
	},
	{
		ID: "IC006", Version: "1", Name: "OS package-manager commands", Category: "runtime-tooling",
		Description: "Confirmed OS package-manager command tooling remains at inspected final-image command locations.",
		TargetKinds: []string{"oci-archive"}, Capabilities: []string{"os-package-tools"}, Available: true,
		Confidence: "high", Fix: "For declared runtime images, review keeping installation commands in the builder stage and copying tested runtime contents into a compatible final image. Intentional package-management workloads may retain them. Preserve package databases, conda metadata and shared runtime libraries for behavior and scanner visibility; removing evidence is not vulnerability remediation.",
		References: []string{dockerStageReference, distrolessReference, metadataReference},
		Exceptions: []string{"Package databases, metadata, libraries, documentation and matching basenames alone are not command tooling.", "Intentional package-management and development workloads may retain these tools."},
		Defaults:   profileDefaults(nonLocal, map[string]Severity{"container-runtime": Warning, "container-distroless": Error}, nil),
		Check:      artifactCheck(artifactRule{selector: toolsOf, capability: "os-package-tools", message: "%d OS package-manager command identities are confirmed in the final image.", notes: []string{"Recognition covers typed known command locations, not every possible custom installation path."}, absenceReason: "no confirmed commands at recognized inspected locations; custom installation paths are outside this predicate"}),
	},
	{
		ID: "IC007", Version: "1", Name: "Shell command tooling", Category: "runtime-tooling",
		Description: "Confirmed shell command tooling remains under an explicitly selected shell policy.",
		TargetKinds: []string{"oci-archive"}, Capabilities: []string{"shell-tools"}, Available: true,
		Confidence: "high", Fix: "Review intentional debug and shell-dependent startup exceptions. Validate exec-form startup, activation and runtime behavior before changing to a shell-free compatible runtime base; shell presence alone is not a vulnerability finding.",
		References: []string{distrolessReference},
		Exceptions: []string{"Intentional debug images and shell-dependent startup require an explicit reviewed exception.", "Recognized command locations do not establish absence at custom installation paths."},
		Defaults:   profileDefaults(distrolessOnly, map[string]Severity{"container-distroless": Error}, nil),
		Check:      artifactCheck(artifactRule{selector: shellsOf, capability: "shell-tools", message: "%d shell command identities are confirmed under the selected shell policy.", notes: []string{"Recognition covers typed known command locations, including resolved aliases, not every custom installation path."}, absenceReason: "no confirmed commands at recognized inspected locations; custom installation paths are outside this predicate"}),
	},
}

// ruleIndex is derived from the single registry literal above; it introduces no second identity list.
var ruleIndex = func() map[string]int {
	index := make(map[string]int, len(registry))
	for i, rule := range registry {
		index[rule.ID] = i
	}
	return index
}()

// LookupRule returns an immutable copy of a registered rule's metadata.
func LookupRule(id string) (Rule, bool) {
	i, ok := ruleIndex[id]
	if !ok {
		return Rule{}, false
	}
	return cloneRule(registry[i]), true
}

func lookupRule(id string) (Rule, bool) {
	i, ok := ruleIndex[id]
	if !ok {
		return Rule{}, false
	}
	return registry[i], true
}

// ListRules lists every registered rule, including unavailable design entries
// disclosed with their reason. Each returned rule is a deep copy.
func ListRules() []Rule {
	rules := make([]Rule, 0, len(registry))
	for _, rule := range registry {
		rules = append(rules, cloneRule(rule))
	}
	return rules
}

func cloneRule(rule Rule) Rule {
	rule.TargetKinds = slices.Clone(rule.TargetKinds)
	rule.Capabilities = slices.Clone(rule.Capabilities)
	rule.References = slices.Clone(rule.References)
	rule.Exceptions = slices.Clone(rule.Exceptions)
	defaults := make(map[string]RuleDefault, len(rule.Defaults))
	for profile, d := range rule.Defaults {
		if d.RevisionThreshold != nil {
			threshold := *d.RevisionThreshold
			d.RevisionThreshold = &threshold
		}
		defaults[profile] = d
	}
	rule.Defaults = defaults
	return rule
}
