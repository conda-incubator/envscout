// Package evidence contains source-qualified facts, not policy decisions.
package evidence

import (
	"time"

	"github.com/conda-incubator/envscout/internal/discovery"
	"github.com/conda-incubator/envscout/internal/imageinput"
	"github.com/conda-incubator/envscout/internal/inventory"
	gorattler "github.com/conda-incubator/go-rattler"
)

const (
	Complete     = "complete"
	Partial      = "partial"
	NotCollected = "not_collected"
)

type Issue struct {
	Capability   string `json:"capability"`
	Path         string `json:"path"`
	Message      string `json:"message"`
	AccessDenied bool   `json:"access_denied,omitempty"`
}

// Artifact describes observed content. Bytes are logical payload bytes, not savings.
type Artifact struct {
	Path       string `json:"path"`
	Kind       string `json:"kind"`
	Bytes      int64  `json:"payload_bytes,omitempty"`
	Layer      int    `json:"layer,omitempty"`
	DiffID     string `json:"diff_id,omitempty"`
	BlobDigest string `json:"compressed_digest,omitempty"`
	LayerBytes int64  `json:"compressed_layer_bytes,omitempty"`
	Reference  string `json:"reference,omitempty"`
}

type Prefix struct {
	Kind     string `json:"kind,omitempty"`
	Path     string `json:"path"`
	Revision *int   `json:"revision"`
	Tooling  bool   `json:"tooling"`
	// Records retain canonical metadata and its source path, never inferred packages.
	Records        []inventory.CondaRecord `json:"-"`
	RecordCoverage string                  `json:"record_coverage,omitempty"`
}

// PythonDistribution is an installed Python distribution cataloged by Syft.
// OwnedBy names the conda record owning its distribution metadata, when present.
type PythonDistribution struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Path    string `json:"path"`
	OwnedBy string `json:"owned_by,omitempty"`
}

// LockComparison compares installed conda metadata only, not files or manifests.
type LockComparison struct {
	Path        string                `json:"path"`
	Prefix      string                `json:"prefix"`
	Environment string                `json:"environment"`
	Subdir      string                `json:"subdir"`
	Report      *gorattler.SyncReport `json:"report,omitempty"`
	Reason      string                `json:"reason,omitempty"`
}

type Project struct {
	Path       string `json:"path"`
	Associated bool   `json:"associated"`
	LockPath   string `json:"lock_path,omitempty"`
	Reason     string `json:"reason,omitempty"`
}

type Target struct {
	// AsOf is the evaluation clock supplied by the rule engine for dated policies.
	AsOf               time.Time            `json:"-"`
	ID                 string               `json:"id"`
	Kind               string               `json:"kind"` // dir or oci-archive
	Input              string               `json:"input"`
	Roots              []string             `json:"roots,omitempty"`
	Image              *imageinput.Identity `json:"image,omitempty"`
	Prefixes           []Prefix             `json:"prefixes"`
	Archives           []Artifact           `json:"download_archives"`
	Extracted          []Artifact           `json:"extracted_cache"`
	Tools              []Artifact           `json:"os_package_tools"`
	Shells             []Artifact           `json:"shell_tools"`
	Retained           []Artifact           `json:"retained_cache"`
	RuntimePrefix      string               `json:"runtime_prefix,omitempty"`
	RuntimeUsesTooling bool                 `json:"runtime_uses_tooling"`
	CacheLinked        bool                 `json:"cache_linked"`
	Project            *Project             `json:"project,omitempty"`
	Python             []PythonDistribution `json:"python_distributions,omitempty"`
	Lock               *LockComparison      `json:"lock_comparison,omitempty"`
	// Peers are supplied by Evaluate for cross-environment checks, not serialized.
	Peers    []Prefix          `json:"-"`
	Coverage map[string]string `json:"coverage"`
	Issues   []Issue           `json:"issues"`
}

type Snapshot struct {
	Started    time.Time          `json:"started_at"`
	Targets    []Target           `json:"targets"`
	Issues     []Issue            `json:"issues"`
	Inspection *InspectionSummary `json:"inspection,omitempty"`
}

// InspectionSummary counts local collection results, independently of rule findings.
// AccessErrors counts permission-denied errors, not malformed or linked evidence.
type InspectionSummary struct {
	Found           int `json:"found"`
	Inspected       int `json:"inspected"`
	Failed          int `json:"failed"`
	AccessErrors    int `json:"access_errors"`
	DiscoveryIssues int `json:"discovery_issues"`
}

// Request chooses collectors before I/O. All filesystem reads must remain bounded.
type Request struct {
	Capabilities           []string
	VirtualenvCapabilities []string
	RuntimePrefix          string
	Project                string
}

// ForEnvironment selects only the evidence supported for this environment kind.
func (r Request) ForEnvironment(kind string) Request {
	if kind == discovery.KindVenv {
		r.Capabilities = r.VirtualenvCapabilities
	}
	return r
}

func (t Target) IsVirtualenv() bool {
	return t.Kind == "dir" && len(t.Prefixes) == 1 && t.Prefixes[0].Kind == discovery.KindVenv
}

func Requested(r Request, capability string) bool {
	for _, c := range r.Capabilities {
		if c == capability {
			return true
		}
	}
	return false
}
