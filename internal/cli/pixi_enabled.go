//go:build pixi

package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	gorattler "github.com/conda-incubator/go-rattler"
)

// pixiLockSummary reads a Pixi marker only in opt-in builds. A lock lookup
// describes the lock contents, not the installed packages or manifest freshness.
func pixiLockSummary(prefix string) string {
	marker := filepath.Join(prefix, "conda-meta", "pixi")
	info, err := os.Lstat(marker)
	if os.IsNotExist(err) {
		return ""
	}
	if err != nil || !info.Mode().IsRegular() || info.Size() > 64*1024 {
		return "Pixi lock: unknown (unreadable marker)"
	}
	contents, err := os.ReadFile(marker)
	if err != nil {
		return "Pixi lock: unknown (unreadable marker)"
	}
	var data struct {
		ManifestPath     string `json:"manifest_path"`
		EnvironmentName  string `json:"environment_name"`
		ResolvedPlatform *struct {
			Subdir string `json:"subdir"`
		} `json:"resolved_platform"`
	}
	if json.Unmarshal(contents, &data) != nil || data.ManifestPath == "" || data.EnvironmentName == "" {
		return "Pixi lock: unknown (invalid marker)"
	}
	if !filepath.IsAbs(data.ManifestPath) || strings.ContainsRune(data.ManifestPath, 0) {
		return "Pixi lock: unknown (invalid manifest path)"
	}
	if data.ResolvedPlatform == nil || data.ResolvedPlatform.Subdir == "" || strings.ContainsRune(data.EnvironmentName, 0) || strings.ContainsRune(data.ResolvedPlatform.Subdir, 0) {
		return "Pixi lock: unknown (marker has no resolved platform)"
	}
	lockPath := filepath.Join(filepath.Dir(data.ManifestPath), "pixi.lock")
	lockInfo, err := os.Lstat(lockPath)
	if err != nil || !lockInfo.Mode().IsRegular() {
		return "Pixi lock: unknown (lockfile unavailable)"
	}
	counts, err := gorattler.LockEnvironment(lockPath, data.EnvironmentName, data.ResolvedPlatform.Subdir)
	if err != nil {
		return fmt.Sprintf("Pixi lock: unknown (%v)", err)
	}
	return fmt.Sprintf("Pixi lock: %s/%s; %d conda, %d PyPI (locked, not installed)", data.EnvironmentName, data.ResolvedPlatform.Subdir, counts.Conda, counts.PyPI)
}
