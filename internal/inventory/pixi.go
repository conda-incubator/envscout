package inventory

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	gorattler "github.com/conda-incubator/go-rattler"
)

// PixiMarker selects the installed environment and resolved platform explicitly.
// It does not prove manifest freshness or that the referenced lock is installed.
type PixiMarker struct {
	ManifestPath    string
	EnvironmentName string
	Subdir          string
}

// ParsePixiMarker validates the explicit project, environment and platform selection.
func ParsePixiMarker(contents []byte) (PixiMarker, error) {
	if len(contents) > 64<<10 {
		return PixiMarker{}, fmt.Errorf("pixi marker exceeds 64 KiB")
	}
	var data struct {
		ManifestPath     string `json:"manifest_path"`
		EnvironmentName  string `json:"environment_name"`
		ResolvedPlatform *struct {
			Subdir string `json:"subdir"`
		} `json:"resolved_platform"`
	}
	if json.Unmarshal(contents, &data) != nil || !filepath.IsAbs(data.ManifestPath) || strings.ContainsAny(data.ManifestPath, "\x00\r\n") || strings.TrimSpace(data.EnvironmentName) == "" || strings.ContainsAny(data.EnvironmentName, "\x00\r\n") {
		return PixiMarker{}, fmt.Errorf("invalid Pixi marker or manifest path")
	}
	if data.ResolvedPlatform == nil || strings.TrimSpace(data.ResolvedPlatform.Subdir) == "" || strings.ContainsAny(data.ResolvedPlatform.Subdir, "\x00\r\n") {
		return PixiMarker{}, fmt.Errorf("pixi marker has no resolved platform")
	}
	return PixiMarker{ManifestPath: data.ManifestPath, EnvironmentName: data.EnvironmentName, Subdir: data.ResolvedPlatform.Subdir}, nil
}

func readPixiFile(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > limit {
		return nil, fmt.Errorf("pixi metadata is not a bounded regular file")
	}
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	f, err := root.Open(filepath.Base(path))
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	opened, err := f.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return nil, fmt.Errorf("pixi metadata changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, fmt.Errorf("pixi metadata could not be read within limit")
	}
	return data, nil
}

// PixiLockSummary reads the Pixi marker for prefixes that carry one and reports
// the locked package counts from the referenced pixi.lock. A lock lookup
// describes the lock contents, not the installed packages or manifest freshness.
// It returns an empty string when prefix has no Pixi marker.
func PixiLockSummary(prefix string) string {
	marker := filepath.Join(prefix, "conda-meta", "pixi")
	contents, err := readPixiFile(marker, 64<<10)
	if os.IsNotExist(err) {
		return ""
	}
	if err != nil {
		return "Pixi lock: unknown (unreadable marker)"
	}
	data, err := ParsePixiMarker(contents)
	if err != nil {
		return "Pixi lock: unknown (invalid marker or missing resolved platform)"
	}
	lockPath := filepath.Join(filepath.Dir(data.ManifestPath), "pixi.lock")
	lock, err := readPixiFile(lockPath, 1<<20)
	if err != nil {
		return "Pixi lock: unknown (lockfile unavailable)"
	}
	packages, err := gorattler.LockPackages(lock, data.EnvironmentName, data.Subdir)
	if err != nil {
		return "Pixi lock: unknown (lock selection could not be parsed)"
	}
	var counts gorattler.PackageCounts
	for _, p := range packages {
		switch p.Kind {
		case "conda":
			counts.Conda++
		case "pypi":
			counts.PyPI++
		}
	}
	return fmt.Sprintf("Pixi lock: %s/%s; %d conda, %d PyPI (locked, not installed)", data.EnvironmentName, data.Subdir, counts.Conda, counts.PyPI)
}
