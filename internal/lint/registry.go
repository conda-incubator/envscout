package lint

import "slices"

var profiles = []string{"local", "container", "container-runtime", "container-distroless", "container-development"}

const (
	condaCleanReference  = "https://docs.conda.io/projects/conda/en/stable/commands/clean.html"
	dockerStageReference = "https://docs.docker.com/build/building/multi-stage/"
	dockerCacheReference = "https://docs.docker.com/build/cache/optimize/"
	distrolessReference  = "https://github.com/GoogleContainerTools/distroless"
	metadataReference    = "https://github.com/GoogleContainerTools/distroless/blob/main/PACKAGE_METADATA.md"
)

var registry = []Rule{
	{
		ID: "EC001", Version: "1", Name: "History revision review", Category: "history",
		Description: "Readable conda history revision meets the configured transaction-count threshold.",
		TargetKinds: []string{"dir", "oci-archive"}, Capabilities: []string{"prefixes", "history"}, Available: true,
		References: []string{"https://docs.conda.io/projects/conda/en/stable/user-guide/tasks/manage-environments.html"},
		Exceptions: []string{"Revision counts do not measure drift, age, corruption, pip edits or vulnerabilities."},
	},
	{
		ID: "EC002", Version: "1", Name: "Installed Pixi lock synchronization", Category: "reproducibility",
		Description: "Authoritatively compare the installed Pixi selection with its resolved lock.",
		TargetKinds: []string{"dir"}, Capabilities: []string{"project-association", "installed-lock"},
		UnavailableReason: "This build has no authoritative Pixi installed-lock hash verification API.",
		References:        []string{"https://pixi.sh/latest/workspace/lockfile/"},
		Exceptions:        []string{"Missing markers and unsupported hash algorithms cannot establish a mismatch."},
	},
	{
		ID: "EC003", Version: "1", Name: "Manifest lock synchronization", Category: "reproducibility",
		Description: "Authoritatively compare a supported manifest with its resolved lock.",
		TargetKinds: []string{"dir"}, Capabilities: []string{"project-association", "manifest-lock"},
		UnavailableReason: "This build has no authoritative Pixi manifest-lock comparison API.",
		References:        []string{"https://pixi.sh/latest/workspace/lockfile/"},
		Exceptions:        []string{"Timestamps and package counts do not establish stale resolution."},
	},
	{
		ID: "EC004", Version: "1", Name: "Associated project lock review", Category: "reproducibility",
		Description: "An explicitly associated local project has no verified resolved lock in its inspected scope.",
		TargetKinds: []string{"dir"}, Capabilities: []string{"project-association"}, Available: true,
		References: []string{"https://pixi.sh/latest/workspace/lockfile/"},
		Exceptions: []string{"Unassociated prefixes and absent runtime-image lockfiles are not violations.", "An unverified existing lock is unknown, not an absent lock."},
	},
	{
		ID: "IC001", Version: "1", Name: "Final image download archives", Category: "footprint",
		Description: "Download archives remain in a confirmed final-image conda package cache.",
		TargetKinds: []string{"oci-archive"}, Capabilities: []string{"final-cache"}, Available: true,
		References: []string{condaCleanReference, dockerCacheReference},
		Exceptions: []string{"Only confirmed cache-context archives count; payload bytes are not predicted savings."},
	},
	{
		ID: "IC002", Version: "1", Name: "Final image extracted package cache", Category: "footprint",
		Description: "Extracted package entries remain in a confirmed final-image conda package cache.",
		TargetKinds: []string{"oci-archive"}, Capabilities: []string{"final-cache", "cache-link-dependencies"}, Available: true,
		References: []string{condaCleanReference, dockerStageReference},
		Exceptions: []string{"Required cache links or incomplete linkage inspection make cleanup unsafe or unknown.", "Hardlinked logical bytes are not unique or reclaimable bytes."},
	},
	{
		ID: "IC003", Version: "1", Name: "Tooling and application prefixes", Category: "runtime-layout",
		Description: "A confirmed tooling prefix coexists with a nested or explicitly asserted distinct application prefix.",
		TargetKinds: []string{"oci-archive"}, Capabilities: []string{"prefixes", "tooling-prefix", "runtime-config"}, Available: true,
		References: []string{dockerStageReference},
		Exceptions: []string{"Application-in-base images are valid.", "Runtime configuration is supporting evidence, not proof that a prefix is unused."},
	},
	{
		ID: "IC004", Version: "1", Name: "Retained layer cache content", Category: "footprint",
		Description: "Confirmed hidden or replaced cache references remain in final-image referenced layers.",
		TargetKinds: []string{"oci-archive"}, Capabilities: []string{"layer-retention"}, Available: true,
		References: []string{dockerStageReference, dockerCacheReference},
		Exceptions: []string{"Compressed descriptor bytes describe whole layers, never per-file reclaimable savings.", "Surviving cache hardlinks must not be classified as runtime-unused content."},
	},
	{
		ID: "IC005", Version: "1", Name: "Runtime stage review", Category: "runtime-layout",
		Description: "Contextual runtime-stage advice based on independently observed cache and tooling facts; never an additional CI failure.",
		TargetKinds: []string{"oci-archive"}, Capabilities: []string{"prefixes", "tooling-prefix", "final-cache", "runtime-config", "os-package-tools"}, Available: true,
		References: []string{dockerStageReference, distrolessReference, metadataReference},
		Exceptions: []string{"Image contents cannot establish Dockerfile build stages or compatible runtime ABI."},
	},
	{
		ID: "IC006", Version: "1", Name: "OS package-manager commands", Category: "runtime-tooling",
		Description: "Confirmed OS package-manager command tooling remains at inspected final-image command locations.",
		TargetKinds: []string{"oci-archive"}, Capabilities: []string{"os-package-tools"}, Available: true,
		References: []string{dockerStageReference, distrolessReference, metadataReference},
		Exceptions: []string{"Package databases, metadata, libraries, documentation and matching basenames alone are not command tooling.", "Intentional package-management and development workloads may retain these tools."},
	},
	{
		ID: "IC007", Version: "1", Name: "Shell command tooling", Category: "runtime-tooling",
		Description: "Confirmed shell command tooling remains under an explicitly selected shell policy.",
		TargetKinds: []string{"oci-archive"}, Capabilities: []string{"shell-tools"}, Available: true,
		References: []string{distrolessReference},
		Exceptions: []string{"Intentional debug images and shell-dependent startup require an explicit reviewed exception.", "Recognized command locations do not establish absence at custom installation paths."},
	},
}

func init() {
	for i := range registry {
		rule := &registry[i]
		rule.Defaults = make(map[string]RuleDefault, len(profiles))
		for _, profile := range profiles {
			d := RuleDefault{Severity: "info"}
			runtime := profile == "container-runtime" || profile == "container-distroless"
			switch rule.ID {
			case "EC001":
				d.Enabled = profile == "local" || profile == "container-development"
				threshold := 10
				d.RevisionThreshold = &threshold
			case "EC002", "EC003":
				d.Enabled = profile == "local"
				d.Severity = "warning"
			case "EC004":
				d.Enabled = profile == "local"
			case "IC001", "IC002":
				d.Enabled = profile != "local"
				if runtime {
					d.Severity = "warning"
				}
			case "IC003", "IC006":
				d.Enabled = profile != "local"
				if rule.ID == "IC006" && runtime {
					d.Severity = "warning"
					if profile == "container-distroless" {
						d.Severity = "error"
					}
				}
			case "IC004":
				d.Enabled = runtime
				d.Severity = "warning"
			case "IC005":
				d.Enabled = runtime
			case "IC007":
				d.Enabled = profile == "container-distroless"
				if d.Enabled {
					d.Severity = "error"
				}
			}
			rule.Defaults[profile] = d
		}
	}
}

// ListRules lists implemented predicates only. Unavailable design entries are
// disclosed in evaluation outcomes, not advertised as implemented checks.
func ListRules() []Rule {
	rules := make([]Rule, 0, len(registry))
	for _, rule := range registry {
		if !rule.Available {
			continue
		}
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
		rules = append(rules, rule)
	}
	return rules
}

func lookupRule(id string) (Rule, bool) {
	for _, rule := range registry {
		if rule.ID == id {
			return rule, true
		}
	}
	return Rule{}, false
}
