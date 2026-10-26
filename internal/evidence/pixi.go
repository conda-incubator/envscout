package evidence

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/conda-incubator/envscout/internal/inventory"
	gorattler "github.com/conda-incubator/go-rattler"
	"go.yaml.in/yaml/v3"
)

// Presence validation selects only declared lock entries, never a host platform
// or a guessed default environment. R2 parses Pixi, not the other lock formats.
func validatePixiLock(data []byte) error {
	var header struct {
		Version      int `yaml:"version"`
		Environments map[string]struct {
			Packages map[string]yaml.Node `yaml:"packages"`
		} `yaml:"environments"`
	}
	if err := yaml.Unmarshal(data, &header); err != nil || header.Version == 0 || header.Environments == nil {
		return fmt.Errorf("invalid Pixi lock structure")
	}
	var selections [][2]string
	for environment, entry := range header.Environments {
		for subdir := range entry.Packages {
			selections = append(selections, [2]string{environment, subdir})
		}
	}
	if len(selections) == 0 || len(selections) > hostEntryLimit {
		return fmt.Errorf("pixi lock has no supported bounded selections")
	}
	sort.Slice(selections, func(i, j int) bool {
		if selections[i][0] != selections[j][0] {
			return selections[i][0] < selections[j][0]
		}
		return selections[i][1] < selections[j][1]
	})
	// R2 parses the whole document when validating a declared selection.
	_, err := gorattler.LockPackages(data, selections[0][0], selections[0][1])
	return err
}

func collectHostPixi(ctx context.Context, target *Target, req Request) {
	prefix := target.Prefixes[0]
	root, err := os.OpenRoot(prefix.Path)
	if err != nil {
		if Requested(req, "installed-lock") {
			target.Lock = &LockComparison{Prefix: prefix.Path, Reason: "Pixi marker filesystem unavailable"}
			hostIssue(target, "installed-lock", prefix.Path, target.Lock.Reason)
		}
		return
	}
	data, err := readHostMetadata(ctx, root, filepath.Join("conda-meta", "pixi"), 64<<10)
	_ = root.Close()
	if os.IsNotExist(err) {
		return // no marker is an explicit not-applicable fact
	}
	comparison := &LockComparison{Prefix: prefix.Path}
	unknown := func(reason, path string) {
		comparison.Reason = reason
		if Requested(req, "installed-lock") {
			target.Lock = comparison
			hostIssue(target, "installed-lock", path, reason)
		}
	}
	if err != nil {
		unknown("Pixi marker is not readable bounded regular metadata", filepath.Join(prefix.Path, "conda-meta/pixi"))
		return
	}
	marker, err := inventory.ParsePixiMarker(data)
	if err != nil {
		unknown("Pixi marker lacks a valid explicit manifest, environment, or resolved platform", filepath.Join(prefix.Path, "conda-meta/pixi"))
		return
	}
	project := filepath.Dir(marker.ManifestPath)
	comparison.Path, comparison.Environment, comparison.Subdir = filepath.Join(project, "pixi.lock"), marker.EnvironmentName, marker.Subdir
	if req.Project != "" {
		explicit, err := filepath.Abs(req.Project)
		if err != nil || explicit != project {
			unknown("explicit project does not match the prefix's Pixi marker association", comparison.Path)
			return
		}
	}
	if !Requested(req, "installed-lock") {
		return
	}
	target.Lock = comparison
	if prefix.RecordCoverage != Complete {
		unknown("installed conda records are incomplete; lock comparison was not run", prefix.Path)
		return
	}
	info, err := os.Lstat(project)
	if err != nil || !info.IsDir() {
		unknown("marker-associated project is inaccessible or linked", project)
		return
	}
	projectRoot, err := os.OpenRoot(project)
	if err != nil {
		unknown("marker-associated project is unavailable", project)
		return
	}
	lock, err := readHostMetadata(ctx, projectRoot, "pixi.lock", hostMetadataLimit)
	_ = projectRoot.Close()
	if err != nil || len(lock) == 0 {
		unknown("selected Pixi lock is unavailable, linked, empty, or oversized", comparison.Path)
		return
	}
	// Selection is exact, including marker subdir. LockSync asserts a complete
	// conda set, so it is never called with partial installed records.
	installed := make([]gorattler.PrefixRecord, 0, len(prefix.Records))
	for _, located := range prefix.Records {
		installed = append(installed, located.Record)
	}
	report, err := gorattler.LockSync(lock, marker.EnvironmentName, marker.Subdir, installed)
	if err != nil {
		unknown("selected Pixi lock environment/platform could not be parsed or compared", comparison.Path)
		return
	}
	comparison.Report = &report
	comparison.Reason = "installed conda metadata comparison only; PyPI, installed files, and manifest freshness are not verified"
	if !report.Complete {
		hostIssue(target, "installed-lock", comparison.Path, "selected installed-lock comparison includes unknown metadata")
	}
}
