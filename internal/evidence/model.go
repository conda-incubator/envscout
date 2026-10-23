// Package evidence contains source-qualified facts, not policy decisions.
package evidence

import (
	"time"

	"github.com/conda-incubator/envscout/internal/imageinput"
)

const (
	Complete     = "complete"
	Partial      = "partial"
	NotCollected = "not_collected"
)

type Issue struct {
	Capability string `json:"capability"`
	Path       string `json:"path"`
	Message    string `json:"message"`
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
	Path     string `json:"path"`
	Revision *int   `json:"revision"`
	Tooling  bool   `json:"tooling"`
}

type Project struct {
	Path         string `json:"path"`
	Associated   bool   `json:"associated"`
	LockPath     string `json:"lock_path,omitempty"`
	LockVerified bool   `json:"lock_verified"`
	Reason       string `json:"reason,omitempty"`
}

type Target struct {
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
	Coverage           map[string]string    `json:"coverage"`
	Issues             []Issue              `json:"issues"`
}

type Snapshot struct {
	Started time.Time `json:"started_at"`
	Targets []Target  `json:"targets"`
	Issues  []Issue   `json:"issues"`
}

// Request chooses collectors before I/O. All filesystem reads must remain bounded.
type Request struct {
	Capabilities  []string
	RuntimePrefix string
	Project       string
}

func Requested(r Request, capability string) bool {
	for _, c := range r.Capabilities {
		if c == capability {
			return true
		}
	}
	return false
}
