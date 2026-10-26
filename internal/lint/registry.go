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
		ID: "ENV001", Version: "2", Name: "Many conda transactions", Category: "history",
		Description: "Repeated environment changes make the original dependency choices harder to review and reproduce.",
		TargetKinds: []string{"dir", "oci-archive"}, Capabilities: []string{"prefixes", "history"}, Available: true,
		Confidence: "high", Fix: "Export the prefix with `conda env export --prefix PATH --from-history`, review the requested dependencies, and create a fresh environment from that specification.",
		References:                []string{"https://docs.conda.io/projects/conda/en/stable/user-guide/tasks/manage-environments.html"},
		Exceptions:                []string{"The revision threshold uses conda's zero-based last transaction index; the displayed transaction count is revision + 1.", "History does not prove drift or cover pip installs or file edits. A from-history export is not a resolved lock."},
		Defaults:                  profileDefaults([]string{"local", "container-development"}, nil, new(defaultRevisionThreshold)),
		SupportsRevisionThreshold: true, Check: checkRevision,
	},
	{
		ID: "ENV002", Version: "2", Name: "Project has no lockfile", Category: "reproducibility",
		Description: "A resolved lock records dependency choices that a manifest alone leaves open.",
		TargetKinds: []string{"dir"}, Capabilities: []string{"project-association"}, Available: true,
		Confidence: "high", Fix: "In the associated project, run `pixi lock`, `conda-lock lock`, or the locking command for its package manager.",
		References: []string{"https://pixi.sh/latest/workspace/lockfile/", "https://conda.github.io/conda-lock/"},
		Exceptions: []string{"Only the explicitly associated project root is checked for recognized lockfiles.", "Presence does not establish installation synchronization; unsupported lock formats receive a presence check only."},
		Defaults:   profileDefaults(localOnly, nil, nil), Check: checkProjectLock,
	},
	{
		ID: "ENV003", Version: "1", Name: "Python packages installed outside conda", Category: "package-ownership",
		Description: "Packages outside conda's file ownership are not managed by conda's dependency solver.",
		TargetKinds: []string{"dir"}, Capabilities: []string{"prefixes", "conda-records", "python-distributions"}, Available: true,
		Confidence: "medium", Fix: "Record intentional pip dependencies in the project specification; install conda dependencies first and pip dependencies last when recreating the environment.",
		References: []string{"https://docs.conda.io/projects/conda/en/stable/user-guide/tasks/manage-environments.html#using-pip-in-an-environment"},
		Exceptions: []string{"Unowned distribution metadata does not identify the installer; manual and editable installs are possible.", "Incomplete conda ownership metadata cannot establish that a distribution is unowned."},
		Defaults:   profileDefaults(localOnly, nil, nil), Check: checkPipInstalled,
	},
	{
		ID: "ENV004", Version: "1", Name: "Python package conflicts with conda metadata", Category: "package-ownership",
		Description: "Different versions of one distribution can leave conda's recorded state inconsistent with Python package metadata.",
		TargetKinds: []string{"dir"}, Capabilities: []string{"prefixes", "conda-records", "python-distributions"}, Available: true,
		Confidence: "medium", Fix: "Recreate the environment with one owner for the conflicting package; avoid installing a different pip version over a conda-managed distribution.",
		References: []string{"https://docs.conda.io/projects/conda/en/stable/user-guide/tasks/manage-environments.html#using-pip-in-an-environment"},
		Exceptions: []string{"A metadata version conflict does not prove Python import precedence or identify the installer; Python versions use PEP 440 equivalence.", "Conda package names and PyPI distribution names are not universally interchangeable; bundles can use different package and distribution version conventions."},
		Defaults:   profileDefaults(localOnly, nil, nil), Check: checkPipShadows,
	},
	{
		ID: "ENV005", Version: "1", Name: "Extra packages in the tooling environment", Category: "environment-layout",
		Description: "Application dependencies in the installer environment couple its maintenance to project dependencies.",
		TargetKinds: []string{"dir"}, Capabilities: []string{"prefixes", "conda-records"}, Available: true,
		Confidence: "medium", Fix: "Create a separate project environment with `conda create --name PROJECT PACKAGE...` and keep the installer environment focused on its tooling.",
		References: []string{"https://docs.conda.io/projects/conda/en/stable/user-guide/tasks/manage-environments.html"},
		Exceptions: []string{"A conda/mamba-containing prefix is a tooling candidate, not proof of the installation's base prefix or application use.", "Packages outside the tools' declared dependency closure may be intentional tooling extensions."},
		Defaults:   profileDefaults(localOnly, nil, nil), Check: checkWorkingBase,
	},
	{
		ID: "ENV006", Version: "1", Name: "Duplicate conda package sets", Category: "environment-layout",
		Description: "Repeated conda package sets may duplicate environment maintenance and disk usage.",
		TargetKinds: []string{"dir"}, Capabilities: []string{"prefixes", "conda-records"}, Available: true,
		Confidence: "high", Fix: "Review the listed prefixes and remove an unused one with `conda env remove --prefix PATH` only after checking its project references.",
		References: []string{"https://docs.conda.io/projects/conda/en/stable/user-guide/tasks/manage-environments.html#removing-an-environment"},
		Exceptions: []string{"Only prefixes in the requested discovery scope are compared.", "Matching conda identities do not establish matching pip packages, files, configuration or runtime behavior, or predict disk savings."},
		Defaults:   profileDefaults(localOnly, nil, nil), Check: checkDuplicates, prepare: prepareDuplicates,
	},
	{
		ID: "ENV007", Version: "1", Name: "Defaults and conda-forge mixed", Category: "channels",
		Description: "Mixing defaults and conda-forge can combine packages built against different dependency assumptions.",
		TargetKinds: []string{"dir"}, Capabilities: []string{"prefixes", "conda-records"}, Available: true,
		Confidence: "high", Fix: "Choose one channel family, set strict channel priority, and recreate the environment; for conda-forge use `conda create --override-channels -c conda-forge --strict-channel-priority --name PROJECT PACKAGE...`.",
		References: []string{"https://conda-forge.org/docs/user/tipsandtricks/", "https://docs.conda.io/projects/conda/en/stable/user-guide/tasks/manage-channels.html"},
		Exceptions: []string{"Intentional mixtures are possible; this check does not prove an ABI failure.", "Only canonical official channel identities are classified; custom aliases and defaults multichannel expansion are unsupported."},
		Defaults:   profileDefaults(localOnly, allWarning, nil), Check: checkMixedChannels,
	},
	{
		ID: "ENV008", Version: "1", Name: "Host package cache content", Category: "footprint",
		Description: "Cached downloads and extracted packages consume space and can be shared by several environments.",
		TargetKinds: []string{"dir"}, Capabilities: []string{"prefixes", "conda-records", "host-cache"}, Available: true,
		Confidence: "high", Fix: "Review `conda clean --tarballs --dry-run` and `conda clean --packages --dry-run` before cleaning unused cache content; preserve caches required by symlink-installed environments.",
		References: []string{condaCleanReference},
		Exceptions: []string{"Cache roots come from installed records, not complete conda configuration precedence; archive and extracted observations can represent the same package.", "File payload totals are not unique disk blocks or reclaimable space; hardlinks, shared caches and symlinks require separate review. Do not use --force-pkgs-dirs for symlink-installed environments."},
		Defaults:   profileDefaults(localOnly, nil, nil), Check: checkHostCache,
	},
	{
		ID: "ENV009", Version: "1", Name: "Python version is past upstream end-of-life", Category: "maintenance",
		Description: "Upstream CPython no longer issues fixes for an end-of-life release series.",
		TargetKinds: []string{"dir"}, Capabilities: []string{"prefixes", "conda-records"}, Available: true,
		Confidence: "high", Fix: "Create and test a replacement environment with a supported Python release, for example `conda create --name PROJECT python=3.13 PACKAGE...`.",
		References: []string{"https://devguide.python.org/versions/"},
		Exceptions: []string{"The upstream CPython support table is dated 2026-10-26 and evaluated against the report's evaluation date.", "Vendor-maintained interpreters may have a different support policy; EOL is not a vulnerability finding."},
		Defaults:   profileDefaults(localOnly, allWarning, nil), Check: checkPythonEOL,
	},
	{
		ID: "ENV010", Version: "2", Name: "Installed conda metadata differs from pixi.lock", Category: "reproducibility",
		Description: "Installed conda package metadata differs from the Pixi lock selection used for this prefix.",
		TargetKinds: []string{"dir"}, Capabilities: []string{"prefixes", "conda-records", "installed-lock"}, Available: true,
		Confidence: "high", Fix: "Run `pixi install --environment ENVIRONMENT` in the project that owns the prefix, then repeat this check.",
		References: []string{"https://pixi.sh/latest/workspace/lockfile/"},
		Exceptions: []string{"The Pixi marker supplies the environment and platform; missing selection or incomplete records cannot establish missing packages.", "Only conda metadata identities and available artifact hashes are compared, not PyPI, installed files, Pixi's installed-lock hash or the manifest."},
		Defaults:   profileDefaults(localOnly, allWarning, nil), Check: checkInstalledLock,
	},
	{
		ID: "ENV011", Version: "2", Name: "pixi.lock is stale against its manifest", Category: "reproducibility",
		Description: "A stale manifest/lock selection can omit requested dependency or platform changes.",
		TargetKinds: []string{"dir"}, Capabilities: []string{"project-association", "manifest-lock"},
		UnavailableReason: "go-rattler does not provide authoritative Pixi manifest/lock synchronization; MatchSpec matching covers only part of that contract.",
		Fix:               "Run `pixi lock` in the project to refresh its resolved dependency selections.",
		References:        []string{"https://pixi.sh/latest/workspace/lockfile/"},
		Exceptions:        []string{"Timestamps, package counts and satisfying individual conda specs do not establish manifest/lock freshness."},
		Defaults:          profileDefaults(localOnly, allWarning, nil),
	},
	{
		ID: "ENV012", Version: "1", Name: "Requested packages have no version constraint", Category: "reproducibility",
		Description: "An unconstrained request can select a different version when the environment is recreated.",
		TargetKinds: []string{"dir"}, Capabilities: []string{"prefixes", "conda-records"}, Available: true,
		Confidence: "high", Fix: "Add suitable version constraints to the project specification and resolve a lock with `pixi lock` or `conda-lock lock`.",
		References: []string{"https://docs.conda.io/projects/conda/en/stable/user-guide/concepts/pkg-specs.html"},
		Exceptions: []string{"Missing requested-spec metadata is not an unconstrained request.", "A version range is a constraint even when it is not an exact version/build pin; this check does not prove installed drift.", "If a record has several requested specs, any unconstrained request is reported; this check does not test whether the installed version satisfies them."},
		Defaults:   profileDefaults(localOnly, nil, nil), Check: checkRequestedSpecs,
	},
	{
		ID: "ENV013", Version: "1", Name: "CA packages below eMudhra remediation minimum", Category: "security-maintenance",
		Description: "Applications using an environment's CA packages need the distribution's recommended updates following the October 2026 eMudhra intermediate-certificate compromise.",
		TargetKinds: []string{"dir", "oci-archive"}, Capabilities: []string{"prefixes", "conda-records"}, Available: true,
		Confidence: "high", Fix: "Update certifi to >=2026.10.19 and ca-certificates to >=2026.10.19 on conda-forge or >=2026.10.20 on Anaconda main, in each affected prefix; update image builds and project locks as appropriate. Keep certificate verification enabled.",
		References: []string{"https://conda.org/blog/2026-10-21-emudhra-security-updates/", "https://github.com/conda-forge/conda-forge.github.io/issues/2967", "https://github.com/certifi/python-certifi/security/advisories/GHSA-6q48-6c7w-9gw2"},
		Exceptions: []string{"Minimums were verified on 2026-10-26 for the official conda-forge and Anaconda main channels; custom or missing channel identities are unknown.", "certifi 2026.10.18 already fixes the incident but falls below the distributions' recommended minimum; older metadata is not proof that an affected certificate remains or is trusted.", "Only conda package metadata is checked, not pip distributions, vendored copies, PEM contents, custom CA files or the operating system trust store.", "Python/package pins or retired platforms may prevent updates; use a supported environment or distribution rather than disabling TLS verification."},
		Defaults:   profileDefaults(profiles, allWarning, nil), Check: checkCAPackages,
	},
	{
		ID: "IMG001", Version: "2", Name: "Package archives shipped in image", Category: "footprint",
		Description: "Cached downloads add content to the image after installation has finished.",
		TargetKinds: []string{"oci-archive"}, Capabilities: []string{"final-cache"}, Available: true,
		Confidence: "high", Fix: "Add `conda clean --tarballs -y` to the same `RUN` step that installs packages, or keep downloads in a BuildKit cache mount.",
		References: []string{condaCleanReference, dockerCacheReference},
		Exceptions: []string{"Only canonical package archive filenames inside observed package caches count; archive bytes are not format-verified.", "Runtime package installation may intentionally use archives. File payload bytes are not predicted image-size savings."},
		Defaults:   profileDefaults(nonLocal, map[string]Severity{"container-runtime": Warning, "container-distroless": Warning}, nil),
		Check:      artifactCheck(artifactRule{selector: archivesOf, capability: "final-cache", message: "%d package archives remain in the image"}),
	},
	{
		ID: "IMG002", Version: "2", Name: "Extracted package cache shipped in image", Category: "footprint",
		Description: "Extracted caches can leave installation content in the image that its application does not need.",
		TargetKinds: []string{"oci-archive"}, Capabilities: []string{"final-cache", "cache-link-dependencies"}, Available: true,
		Confidence: "high", Fix: "Review `conda clean --packages --dry-run` during installation, or copy a tested application prefix into a compatible runtime stage. Preserve observed cache dependencies.",
		References: []string{condaCleanReference, dockerStageReference},
		Exceptions: []string{"Symlinks can require cache paths; unlinking one ordinary hardlink does not erase another hardlink's content.", "Image hardlink identity can be unresolved. File payload totals are not unique or reclaimable bytes, and --packages removes only unused cache entries."},
		Defaults:   profileDefaults(nonLocal, map[string]Severity{"container-runtime": Warning, "container-distroless": Warning}, nil),
		Check:      checkExtractedCache,
	},
	{
		ID: "IMG003", Version: "2", Name: "Installer shipped alongside application environment", Category: "runtime-layout",
		Description: "A separate installer prefix can add build tooling to an image whose application uses another prefix.",
		TargetKinds: []string{"oci-archive"}, Capabilities: []string{"prefixes", "tooling-prefix", "runtime-config"}, Available: true,
		Confidence: "medium", Fix: "Copy the tested application prefix into a compatible runtime stage and validate startup, activation, runtime libraries and relocation.",
		References: []string{dockerStageReference},
		Exceptions: []string{"Application-in-base images are valid; direct startup using tooling or its prefix passes this check.", "Nested envs/ paths identify application candidates, not exclusive runtime use. Shell wrappers are not interpreted."},
		Defaults:   profileDefaults(nonLocal, nil, nil), Check: checkPrefixRoles,
	},
	{
		ID: "IMG004", Version: "2", Name: "Cache hidden by later layers still ships", Category: "footprint",
		Description: "Deleting or replacing files in a later layer does not remove their earlier layer content from the image.",
		TargetKinds: []string{"oci-archive"}, Capabilities: []string{"layer-retention"}, Available: true,
		Confidence: "high", Fix: "Install and clean caches in the same `RUN` step, use `RUN --mount=type=cache` for downloads, or copy the tested prefix into a runtime stage.",
		References: []string{dockerStageReference, dockerCacheReference},
		Exceptions: []string{"Compressed descriptor bytes describe whole layers, never per-file reclaimable savings; displayed source layers are numbered from one.", "Collection does not identify deletion layers or Dockerfile instructions. Surviving cache hardlinks must not be classified as runtime-unused content."},
		Defaults:   profileDefaults(runtimeOnly, allWarning, nil),
		Check:      artifactCheck(artifactRule{selector: retainedOf, capability: "layer-retention", byteUnit: "retained file payload bytes; not compressed or reclaimable bytes", message: "%d cache entries hidden or replaced in the final filesystem remain in earlier image layers"}),
	},
	{
		ID: "IMG005", Version: "2", Name: "Package manager executables shipped in image", Category: "runtime-tooling",
		Description: "Package-manager executables add installation tooling and attack surface to an application image.",
		TargetKinds: []string{"oci-archive"}, Capabilities: []string{"os-package-tools"}, Available: true,
		Confidence: "high", Fix: "Install dependencies in a builder stage and copy tested runtime contents into a compatible final image; preserve package databases, metadata and required libraries.",
		References: []string{dockerStageReference, distrolessReference, metadataReference},
		Exceptions: []string{"Package databases, metadata, libraries, documentation and matching basenames alone are not command tooling.", "Only recognized command locations are inspected; executable presence does not prove installation will succeed.", "Intentional package-management and development workloads may retain these tools."},
		Defaults:   profileDefaults(nonLocal, map[string]Severity{"container-runtime": Warning, "container-distroless": Error}, nil),
		Check:      artifactCheck(artifactRule{selector: toolsOf, capability: "os-package-tools", message: "%d package-manager executables remain in the image", absenceReason: "no package-manager executables at the recognized locations"}),
	},
	{
		ID: "IMG006", Version: "2", Name: "Shell present under shell-free image policy", Category: "runtime-tooling",
		Description: "A shell conflicts with the shell-free policy selected by the distroless profile or this explicit rule.",
		TargetKinds: []string{"oci-archive"}, Capabilities: []string{"shell-tools"}, Available: true,
		Confidence: "high", Fix: "Use exec-form `CMD` with a shell-free compatible base. For intentional shells, select `--profile container-runtime` and remove any explicit IMG006 enablement, or record a reviewed suppression.",
		References: []string{distrolessReference},
		Exceptions: []string{"Intentional debug images and shell-dependent startup require an explicit reviewed exception.", "Recognized command locations do not establish absence at custom installation paths."},
		Defaults:   profileDefaults(distrolessOnly, map[string]Severity{"container-distroless": Error}, nil),
		Check:      artifactCheck(artifactRule{selector: shellsOf, capability: "shell-tools", message: "%d shell executables remain in the image", absenceReason: "no shell executables at the recognized locations"}),
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
