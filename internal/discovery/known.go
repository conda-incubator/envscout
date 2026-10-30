package discovery

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Known-location candidates are hints, not evidence: each is inspected with the same prefix
// rules as an explicit root. An image never receives host hints.
const (
	maxRegistryBytes    = 1 << 20
	maxRegistryLines    = 1000
	maxCondarcBytes     = 1 << 20
	maxContainerEntries = 1000
	maxHintCandidates   = 256
	maxPathListBytes    = 16 << 10
	maxHintPathBytes    = 4096
	maxRegistryLineLen  = maxHintPathBytes
)

// kind of a candidate: a prefix is inspected directly, a root is a prefix when it holds
// conda-meta and always contributes its envs/ child, and a container contributes each child.
type kind uint8

const (
	kindPrefix kind = iota
	kindRoot
	kindContainer
)

// installNames shared by every base directory. Each base expands to one candidate per name.
var installNames = []string{"miniconda3", "anaconda3", "miniforge3", "mambaforge"}

// candidate is one resolved location to probe. source is the reporting key for hints.
type candidate struct {
	source     string
	path       string
	kind       kind
	configured bool
}

// knownCandidates resolves the fixed install layouts and the configured hints, in stable order.
func knownCandidates(inputs knownInputs, col *collector) []candidate {
	out := appendFixed(nil, inputs)
	if inputs.cwd != "" {
		out = append(out, newCandidate("cwd/.pixi/envs", filepath.Join(inputs.cwd, ".pixi", "envs"), kindContainer, false))
		out = append(out, newCandidate("cwd/prefix", inputs.cwd, kindPrefix, false))
		for _, name := range []string{".venv", "venv", ".env", ".virtualenv"} {
			out = append(out, newCandidate("cwd/"+name, filepath.Join(inputs.cwd, name), kindPrefix, false))
		}
	}
	out = append(out, venvCandidates(inputs, col)...)
	if inputs.goos == "darwin" {
		for _, product := range []string{"/opt/homebrew/Caskroom", "/usr/local/Caskroom"} {
			for _, name := range []string{"miniconda", "anaconda"} {
				for _, version := range caskroomVersions(filepath.Join(product, name), col) {
					out = append(out, newCandidate("darwin/caskroom", version, kindRoot, false))
					for _, sub := range installNames {
						out = append(out, newCandidate("darwin/caskroom", filepath.Join(version, sub), kindRoot, false))
					}
				}
			}
		}
	}
	out = append(out, envHintCandidates(inputs, col)...)
	for _, p := range readRegistry(inputs, col) {
		out = append(out, newCandidate("conda/environments.txt", p, kindPrefix, false))
	}
	for _, p := range condaEnvsDirs(inputs, col) {
		out = append(out, newCandidate("condarc/envs_dirs", p, kindContainer, true))
	}
	if len(out) > maxHintCandidates {
		col.addIssue("known locations", fmt.Errorf("%d candidates exceed the limit of %d; probing the first %d", len(out), maxHintCandidates, maxHintCandidates))
		out = out[:maxHintCandidates]
	}
	return out
}

// venvCandidates resolves virtualenv locations. Active and project hints must be absolute
// and are probed directly; container hints contribute their immediate children. Nothing is
// walked recursively, and no uv download or managed-Python directory is included.
func venvCandidates(inputs knownInputs, col *collector) []candidate {
	out := configuredHints(inputs, []configuredHint{
		{"VIRTUAL_ENV", kindPrefix, ""},
		{"UV_PROJECT_ENVIRONMENT", kindPrefix, ""},
		{"WORKON_HOME", kindContainer, ""},
		{"POETRY_VIRTUALENVS_PATH", kindContainer, ""},
	}, col)
	if cache := inputs.env["POETRY_CACHE_DIR"]; cache != "" && validHintPath("POETRY_CACHE_DIR", cache, col) {
		out = append(out, newCandidate("POETRY_CACHE_DIR", filepath.Join(cache, "virtualenvs"), kindContainer, true))
	} else if cache := defaultPoetryCache(inputs); cache != "" {
		out = append(out, newCandidate("poetry/cache", cache, kindContainer, false))
	}
	if inputs.home != "" {
		for _, name := range []string{".virtualenvs", ".venvs"} {
			out = append(out, newCandidate("home/"+name, filepath.Join(inputs.home, name), kindContainer, false))
		}
	}
	return out
}

// defaultPoetryCache returns Poetry's default virtualenvs directory for the injected platform,
// or "" when the platform base directory is unknown.
func defaultPoetryCache(inputs knownInputs) string {
	switch inputs.goos {
	case "windows":
		if base := inputs.env["LOCALAPPDATA"]; base != "" {
			return filepath.Join(base, "pypoetry", "Cache", "virtualenvs")
		}
	case "darwin":
		if inputs.home != "" {
			return filepath.Join(inputs.home, "Library", "Caches", "pypoetry", "virtualenvs")
		}
	default:
		if base := inputs.env["XDG_CACHE_HOME"]; base != "" {
			return filepath.Join(base, "pypoetry", "virtualenvs")
		}
		if inputs.home != "" {
			return filepath.Join(inputs.home, ".cache", "pypoetry", "virtualenvs")
		}
	}
	return ""
}

func newCandidate(source, p string, k kind, configured bool) candidate {
	return candidate{source: source, path: filepath.Clean(p), kind: k, configured: configured}
}

// validHintPath checks configured hints before cleaning or adding layout suffixes.
func validHintPath(source, value string, col *collector) bool {
	switch {
	case len(value) > maxHintPathBytes:
		col.addIssue(source, fmt.Errorf("hint path exceeds known-location limit"))
	case !filepath.IsAbs(value):
		col.addIssue(source, fmt.Errorf("hint must be an absolute path"))
	default:
		return true
	}
	return false
}

type configuredHint struct {
	name string
	kind kind
	tail string
}

// configuredHints preserves row order and validates raw values before adding suffixes.
func configuredHints(inputs knownInputs, rows []configuredHint, col *collector) []candidate {
	var out []candidate
	for _, row := range rows {
		if value := inputs.env[row.name]; value != "" && validHintPath(row.name, value, col) {
			out = append(out, newCandidate(row.name, filepath.Join(value, row.tail), row.kind, true))
		}
	}
	return out
}

// appendFixed appends the platform install layouts. Windows and unix rows never mix; the
// unix-only home/opt rows are gated on goos, not on the host.
func appendFixed(out []candidate, inputs knownInputs) []candidate {
	if inputs.home != "" {
		for _, manager := range []string{".conda", ".pixi"} {
			out = append(out, newCandidate("home/"+manager+"/envs", filepath.Join(inputs.home, manager, "envs"), kindContainer, false))
		}
	}
	type installGroup struct {
		source, base string
		names        []string
	}
	groups := []installGroup{{"home", inputs.home, append([]string{"miniconda", "anaconda", "micromamba"}, installNames...)}}
	if inputs.goos == "windows" {
		groups = append(groups,
			installGroup{"windows/programdata", inputs.env["PROGRAMDATA"], installNames[:3]},
			installGroup{"windows/localappdata", inputs.env["LOCALAPPDATA"], installNames[:2]})
		if base := inputs.env["LOCALAPPDATA"]; base != "" {
			out = append(out, newCandidate("windows/localappdata/conda/envs", filepath.Join(base, "conda", "envs"), kindContainer, false))
		}
	} else {
		if inputs.home != "" {
			groups = append(groups, installGroup{"home/opt", filepath.Join(inputs.home, "opt"), installNames})
		}
		groups = append(groups,
			installGroup{"system/opt", "/opt", installNames},
			installGroup{"system/usr-local", "/usr/local", installNames})
		out = append(out, newCandidate("system/opt-conda", "/opt/conda", kindRoot, false), newCandidate("system/usr-share-conda", "/usr/share/conda", kindRoot, false))
	}
	for _, group := range groups {
		if group.base != "" {
			for _, name := range group.names {
				out = append(out, newCandidate(group.source+"/"+name, filepath.Join(group.base, name), kindRoot, false))
			}
		}
	}
	return out
}

// envHintCandidates resolves the environment-variable hints. A configured value that is
// missing, relative or too long is an issue; CONDA_ENVS_PATH is split on the injected
// platform's separator and each entry is validated by the same rules as a scalar.
func envHintCandidates(inputs knownInputs, col *collector) []candidate {
	out := configuredHints(inputs, []configuredHint{
		{"CONDA_PREFIX", kindPrefix, ""},
		{"CONDA_ROOT", kindRoot, ""},
		{"MAMBA_ROOT_PREFIX", kindRoot, ""},
		{"PIXI_HOME", kindContainer, "envs"},
		{"PIXI_PROJECT_ROOT", kindContainer, filepath.Join(".pixi", "envs")},
	}, col)
	raw := inputs.env["CONDA_ENVS_PATH"]
	if len(raw) > maxPathListBytes {
		col.addIssue("CONDA_ENVS_PATH", fmt.Errorf("path list exceeds known-location size limit"))
		return out
	}
	for _, entry := range strings.Split(raw, inputs.pathSep()) {
		if entry != "" && validHintPath("CONDA_ENVS_PATH", entry, col) {
			out = append(out, newCandidate("CONDA_ENVS_PATH", entry, kindContainer, true))
		}
	}
	return out
}

// caskroomVersions lists one bounded level of a Caskroom product: each version directory
// is a candidate root. It never recurses.
func caskroomVersions(product string, col *collector) []string {
	dir, err := os.Open(product)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		col.addIssue(product, err)
		return nil
	}
	defer func() { _ = dir.Close() }()
	entries, err := dir.ReadDir(maxContainerEntries + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		col.addIssue(product, err)
		return nil
	}
	if len(entries) > maxContainerEntries {
		col.addIssue(product, fmt.Errorf("caskroom exceeds %d entries", maxContainerEntries))
		entries = entries[:maxContainerEntries]
	}
	slices.SortFunc(entries, func(a, b fs.DirEntry) int { return strings.Compare(a.Name(), b.Name()) })
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			out = append(out, filepath.Join(product, e.Name()))
		}
	}
	return out
}

// readBoundedFile returns the contents of a regular file of at most limit bytes. exists is
// false when the path is absent (never an issue here; callers decide). ok is false when an
// issue was recorded and the file must not be used.
func readBoundedFile(path string, limit int64, col *collector) (data []byte, exists, ok bool) {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, false
	}
	if err != nil {
		col.addIssue(path, err)
		return nil, true, false
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		col.addIssue(path, fmt.Errorf("not a regular file of at most %d bytes", limit))
		return nil, true, false
	}
	data, err = os.ReadFile(path)
	if err != nil || int64(len(data)) > limit {
		if err == nil {
			err = fmt.Errorf("file exceeds %d bytes", limit)
		}
		col.addIssue(path, err)
		return nil, true, false
	}
	return data, true, true
}

// readRegistry parses ~/.conda/environments.txt: one absolute prefix per line, bounded by
// size, line count and line length. A missing file is normal; malformed content is an issue.
func readRegistry(inputs knownInputs, col *collector) []string {
	if inputs.home == "" {
		return nil
	}
	registry := filepath.Join(inputs.home, ".conda", "environments.txt")
	data, _, ok := readBoundedFile(registry, maxRegistryBytes, col)
	if !ok {
		return nil
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), maxRegistryLineLen)
	var out []string
	lines := 0
	for scanner.Scan() {
		lines++
		if lines > maxRegistryLines {
			col.addIssue(registry, fmt.Errorf("registry exceeded %d lines", maxRegistryLines))
			break
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if !filepath.IsAbs(line) {
			col.addIssue(registry, fmt.Errorf("registry contains a non-absolute path"))
			continue
		}
		out = append(out, line)
	}
	if err := scanner.Err(); err != nil {
		col.addIssue(registry, fmt.Errorf("read registry: %w", err))
	}
	return out
}

// condarcFile is the typed subset of a condarc that discovery consumes. Conda's full
// configuration precedence is intentionally not implemented; pkgs_dirs is parsed and
// reserved for future cache-prune use.
type condarcFile struct {
	EnvsDirs []string `yaml:"envs_dirs"`
	PkgsDirs []string `yaml:"pkgs_dirs"`
}

// condaEnvsDirs returns envs_dirs values from the readable user condarc files. The explicit
// CONDARC path is configured: when set and missing, that is an issue, not silence.
func condaEnvsDirs(inputs knownInputs, col *collector) []string {
	var out []string
	type source struct {
		path     string
		explicit bool
	}
	var sources []source
	if explicit := inputs.env["CONDARC"]; explicit != "" {
		p, err := expandConfigPath(explicit, inputs)
		if err != nil {
			col.addIssue("CONDARC", err)
		} else {
			sources = append(sources, source{p, true})
		}
	}
	if inputs.home != "" {
		for _, p := range []string{".condarc", filepath.Join(".conda", "condarc"), filepath.Join(".config", "conda", "condarc")} {
			sources = append(sources, source{filepath.Join(inputs.home, p), false})
		}
	}
	for _, src := range sources {
		cfg, ok := loadCondarc(src.path, src.explicit, col)
		if !ok {
			continue
		}
		for _, raw := range cfg.EnvsDirs {
			expanded, err := expandConfigPath(raw, inputs)
			if err != nil {
				col.addIssue(src.path, err)
				continue
			}
			out = append(out, expanded)
		}
	}
	return out
}

// loadCondarc reads one condarc through the typed struct. A missing implicit file is
// ignored; a missing explicit CONDARC or a malformed file is an issue.
func loadCondarc(path string, explicit bool, col *collector) (condarcFile, bool) {
	data, exists, ok := readBoundedFile(path, maxCondarcBytes, col)
	if !exists {
		if explicit {
			col.addIssue(path, fmt.Errorf("configured condarc not found"))
		}
		return condarcFile{}, false
	}
	if !ok {
		return condarcFile{}, false
	}
	var cfg condarcFile
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		col.addIssue(path, fmt.Errorf("malformed condarc: %w", err))
		return condarcFile{}, false
	}
	return cfg, true
}

// expandConfigPath applies a leading ~/ and os.Expand against the injected environment and
// home. The result must be absolute; discovery never guesses a base for a relative path.
func expandConfigPath(raw string, inputs knownInputs) (string, error) {
	value := raw
	if strings.HasPrefix(value, "~/") {
		if inputs.home == "" {
			return "", fmt.Errorf("cannot expand %q without a home directory", raw)
		}
		value = filepath.Join(inputs.home, value[2:])
	}
	value = os.Expand(value, func(name string) string {
		if name == "HOME" && inputs.home != "" {
			return inputs.home
		}
		return inputs.env[name]
	})
	if !filepath.IsAbs(value) {
		return "", fmt.Errorf("path %q is not absolute", raw)
	}
	return filepath.Clean(value), nil
}

// findKnown is the testable core: inputs are injected, nothing else is read from the host.
// A cancelled context returns before any stat or configuration read.
func findKnown(ctx context.Context, inputs knownInputs) (Report, error) {
	report := newReport(ModeKnownLocations)
	if err := ctx.Err(); err != nil {
		return report, err
	}
	col := newCollector(&report)
	col.progress = progressFrom(ctx)
	if inputs.homeErr != nil {
		col.addIssue("home", inputs.homeErr)
	}
	if inputs.cwdErr != nil {
		col.addIssue("cwd", inputs.cwdErr)
	}
	candidates := knownCandidates(inputs, col)
	report.Hints = probeKnown(ctx, inputs.cwd, candidates, col)
	sortReport(&report)
	return report, ctx.Err()
}

// knownInputs carries every host input so tests can supply them deterministically.
type knownInputs struct {
	home, cwd       string
	homeErr, cwdErr error
	goos            string
	env             map[string]string
}

// pathSep is the PATH-list separator for the injected platform, not the test host's.
func (in knownInputs) pathSep() string {
	if in.goos == "windows" {
		return ";"
	}
	return ":"
}

// FindKnown probes bounded host-specific candidate locations. It never walks the home
// directory recursively and never invokes conda.
func FindKnown(ctx context.Context) (Report, error) {
	if err := ctx.Err(); err != nil {
		return newReport(ModeKnownLocations), err
	}
	return findKnown(ctx, systemKnownInputs())
}

// systemKnownInputs snapshots the full environment so ~/ and ${VAR} expansion matches the
// host, with HOME forced to the resolved home directory.
func systemKnownInputs() knownInputs {
	home, homeErr := os.UserHomeDir()
	cwd, cwdErr := os.Getwd()
	env := make(map[string]string)
	for _, kv := range os.Environ() {
		if k, v, ok := strings.Cut(kv, "="); ok {
			env[k] = v
		}
	}
	return knownInputs{home: home, homeErr: homeErr, cwd: cwd, cwdErr: cwdErr, goos: runtime.GOOS, env: env}
}
