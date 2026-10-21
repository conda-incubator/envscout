package discovery

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

// These tables contain candidate locations, not evidence that an environment exists.
// Keep host-specific hints here; an OCI image must derive its own locations.
const (
	condaPrefixVar      = "CONDA_PREFIX"
	condaEnvsPathVar    = "CONDA_ENVS_PATH"
	mambaRootVar        = "MAMBA_ROOT_PREFIX"
	pixiHomeVar         = "PIXI_HOME"
	pixiProjectRootVar  = "PIXI_PROJECT_ROOT"
	maxRegistryBytes    = 1 << 20
	maxRegistryLines    = 1000
	maxHintCandidates   = 256
	maxContainerEntries = 1000
	maxPathListBytes    = 16 << 10
	maxHintPathBytes    = 4096
)

type hintKind uint8

const (
	prefixHint hintKind = iota
	rootHint
	containerHint
)

type locationTemplate struct {
	source string
	path   string
	kind   hintKind
}

var homeLocations = []locationTemplate{
	{"home/.conda/envs", ".conda/envs", containerHint},
	{"home/miniconda3", "miniconda3", rootHint},
	{"home/anaconda3", "anaconda3", rootHint},
	{"home/miniforge3", "miniforge3", rootHint},
	{"home/mambaforge", "mambaforge", rootHint},
	{"home/micromamba", "micromamba", rootHint},
	{"home/.pixi/envs", ".pixi/envs", containerHint},
}

var unixLocations = []locationTemplate{
	{"system/opt-conda", "/opt/conda", rootHint},
}

var windowsLocations = []locationTemplate{
	{"home/AppData/Local/conda/envs", "AppData/Local/conda/envs", containerHint},
}

type knownInputs struct {
	home, cwd, goos string
	env             map[string]string
	pathSeparator   rune
	homeErr, cwdErr error
}

func systemKnownInputs() knownInputs {
	home, homeErr := os.UserHomeDir()
	cwd, cwdErr := os.Getwd()
	inputs := knownInputs{home: home, cwd: cwd, goos: runtime.GOOS, env: make(map[string]string), pathSeparator: os.PathListSeparator, homeErr: homeErr, cwdErr: cwdErr}
	for _, key := range []string{condaPrefixVar, condaEnvsPathVar, mambaRootVar, pixiHomeVar, pixiProjectRootVar} {
		inputs.env[key] = os.Getenv(key)
	}
	return inputs
}

type locationHint struct {
	path, source string
	kind         hintKind
	configured   bool
}

// FindKnownCondaWithProgress checks bounded host hints, without recursively walking home.
func FindKnownCondaWithProgress(progress *Progress) (Report, error) {
	return findKnownConda(systemKnownInputs(), progress)
}

func findKnownConda(inputs knownInputs, progress *Progress) (Report, error) {
	report := Report{Mode: ModeKnownLocations, Roots: []string{}, Hints: []HintSummary{}, Environments: []Environment{}, Issues: []Issue{}}
	results := condaResults{report: &report, seen: make(map[string]bool), progress: progress}
	probeKnownHints(&results, inputs, nil)
	sortReport(&report)
	return report, nil
}

func knownHints(inputs knownInputs, roots []string, report *Report) []locationHint {
	var hints []locationHint
	if roots == nil {
		if inputs.homeErr != nil {
			report.Issues = append(report.Issues, Issue{Path: "home", Error: inputs.homeErr.Error()})
		}
		if inputs.cwdErr != nil {
			report.Issues = append(report.Issues, Issue{Path: "cwd", Error: inputs.cwdErr.Error()})
		}
	}
	add := func(path, source string, kind hintKind, configured bool) {
		if path == "" {
			return
		}
		if len(path) > maxHintPathBytes {
			if configured && roots == nil {
				report.Issues = append(report.Issues, Issue{Path: source, Error: "hint path exceeds known-location limit"})
			}
			return
		}
		if strings.HasPrefix(path, "~/") && inputs.home != "" {
			path = filepath.Join(inputs.home, path[2:])
		}
		if !filepath.IsAbs(path) {
			if configured && roots == nil {
				report.Issues = append(report.Issues, Issue{Path: source, Error: "hint must be an absolute path"})
			}
			return
		}
		hints = append(hints, locationHint{filepath.Clean(path), source, kind, configured})
	}
	add(inputs.env[condaPrefixVar], condaPrefixVar, prefixHint, true)
	add(inputs.env[mambaRootVar], mambaRootVar, rootHint, true)
	if raw := inputs.env[condaEnvsPathVar]; raw != "" {
		if len(raw) > maxPathListBytes {
			if roots == nil {
				report.Issues = append(report.Issues, Issue{Path: condaEnvsPathVar, Error: "path list exceeds known-location size limit"})
			}
		} else {
			separator := inputs.pathSeparator
			if separator == 0 {
				separator = os.PathListSeparator
			}
			paths := strings.Split(raw, string(separator))
			if len(paths) > maxHintCandidates {
				if roots == nil {
					report.Issues = append(report.Issues, Issue{Path: condaEnvsPathVar, Error: "path list exceeds known-location limit"})
				}
				paths = paths[:maxHintCandidates]
			}
			for _, path := range paths {
				add(path, condaEnvsPathVar, containerHint, true)
			}
		}
	}
	if inputs.home != "" {
		for _, template := range homeLocations {
			add(filepath.Join(inputs.home, template.path), template.source, template.kind, false)
		}
		if inputs.goos == "windows" {
			for _, template := range windowsLocations {
				add(filepath.Join(inputs.home, template.path), template.source, template.kind, false)
			}
		}
	}
	if inputs.goos != "windows" {
		for _, template := range unixLocations {
			add(template.path, template.source, template.kind, false)
		}
	}
	if inputs.home != "" {
		registry := filepath.Join(inputs.home, ".conda", "environments.txt")
		if roots == nil {
			if safe, err := safeHintDir(filepath.Dir(registry)); err != nil {
				if roots == nil {
					report.Issues = append(report.Issues, Issue{Path: registry, Error: err.Error()})
				}
			} else if safe {
				paths, err := readRegistry(registry)
				if err != nil && roots == nil {
					report.Issues = append(report.Issues, Issue{Path: registry, Error: err.Error()})
				}
				for _, path := range paths {
					add(path, "conda/environments.txt", prefixHint, false)
				}
			}
		}
	}
	if pixiHome := inputs.env[pixiHomeVar]; pixiHome != "" {
		if !filepath.IsAbs(pixiHome) {
			if roots == nil {
				report.Issues = append(report.Issues, Issue{Path: pixiHomeVar, Error: "hint must be an absolute path"})
			}
		} else {
			add(filepath.Join(pixiHome, "envs"), pixiHomeVar, containerHint, true)
		}
	}
	if inputs.cwd != "" {
		add(filepath.Join(inputs.cwd, ".pixi", "envs"), "cwd/.pixi/envs", containerHint, false)
	}
	if project := inputs.env[pixiProjectRootVar]; project != "" {
		if !filepath.IsAbs(project) {
			if roots == nil {
				report.Issues = append(report.Issues, Issue{Path: pixiProjectRootVar, Error: "hint must be an absolute path"})
			}
		} else {
			add(filepath.Join(project, ".pixi", "envs"), pixiProjectRootVar, containerHint, true)
		}
	}
	return hints
}

func readRegistry(path string) ([]string, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxRegistryBytes {
		return nil, fmt.Errorf("registry is not a regular file of at most %d bytes", maxRegistryBytes)
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
	if err != nil {
		return nil, err
	}
	if !opened.Mode().IsRegular() || opened.Size() > maxRegistryBytes || !os.SameFile(info, opened) {
		return nil, fmt.Errorf("registry is not a regular file of at most %d bytes", maxRegistryBytes)
	}
	scanner := bufio.NewScanner(io.LimitReader(f, maxRegistryBytes+1))
	scanner.Buffer(make([]byte, 4096), 8192)
	var paths []string
	lines := 0
	var invalidLine bool
	for scanner.Scan() {
		lines++
		if lines > maxRegistryLines {
			return paths, fmt.Errorf("registry exceeded %d lines", maxRegistryLines)
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if !filepath.IsAbs(line) {
			invalidLine = true
			continue
		}
		paths = append(paths, line)
	}
	if err := scanner.Err(); err != nil {
		return paths, err
	}
	if invalidLine {
		return paths, fmt.Errorf("registry contains a non-absolute path")
	}
	return paths, nil
}

func inScope(path string, roots []string) bool {
	if roots == nil {
		return true
	}
	for _, root := range roots {
		rel, err := filepath.Rel(root, path)
		if err == nil && rel != ".." && !filepath.IsAbs(rel) && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

func safeHintDir(path string) (bool, error) {
	for current := path; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		if info.Mode()&fs.ModeSymlink != 0 {
			return false, fmt.Errorf("symlink in hint path")
		}
		if current == path && !info.IsDir() {
			return false, fmt.Errorf("hint is not a directory")
		}
		if parent := filepath.Dir(current); parent == current {
			return true, nil
		}
	}
}

func openHintDir(path string, roots []string) (*os.Root, error) {
	if roots == nil {
		return os.OpenRoot(path)
	}
	for _, rootPath := range roots {
		if !inScope(path, []string{rootPath}) {
			continue
		}
		expected, err := os.Lstat(rootPath)
		if err != nil {
			return nil, err
		}
		if !expected.IsDir() {
			return nil, fmt.Errorf("requested root is no longer a directory")
		}
		base, err := os.OpenRoot(rootPath)
		if err != nil {
			return nil, err
		}
		opened, err := base.Stat(".")
		if err != nil || !os.SameFile(expected, opened) {
			_ = base.Close()
			return nil, fmt.Errorf("requested root changed during hint inspection")
		}
		rel, err := filepath.Rel(rootPath, path)
		if err == nil {
			var dir *os.Root
			dir, err = base.OpenRoot(rel)
			_ = base.Close()
			if err != nil {
				return nil, err
			}
			expected, err := os.Lstat(path)
			if err == nil && !expected.IsDir() {
				err = fmt.Errorf("hint is no longer a directory")
			}
			if err == nil {
				var opened os.FileInfo
				opened, err = dir.Stat(".")
				if err == nil && !os.SameFile(expected, opened) {
					err = fmt.Errorf("hint changed during inspection")
				}
			}
			if err != nil {
				_ = dir.Close()
				return nil, err
			}
			return dir, nil
		}
		_ = base.Close()
		return nil, err
	}
	return nil, fmt.Errorf("hint outside requested roots")
}

func probeKnownHints(results *condaResults, inputs knownInputs, roots []string) {
	ctx := results.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	seenHints := make(map[locationHintKey]bool)
	seenPrefixes := make(map[string]bool)
	seenContainers := make(map[string]bool)
	summaries := make(map[string]*HintSummary)
	budget := maxHintCandidates
	moreSkipped := 0
	reportIssue := func(path string, err error) {
		if roots == nil { // Full walks report their own errors and coverage gaps.
			results.addIssue(path, err)
		}
	}
	openDir := func(path string) (*os.Root, error) { return openHintDir(path, roots) }
	for _, hint := range knownHints(inputs, roots, results.report) {
		if ctx.Err() != nil {
			break
		}
		container := hint.path
		if hint.kind == rootHint {
			container = filepath.Join(hint.path, "envs")
		}
		rootInScope := inScope(hint.path, roots)
		if !rootInScope && (hint.kind != rootHint || !inScope(container, roots)) {
			continue
		}
		summary := summaries[hint.source]
		if summary == nil {
			summary = &HintSummary{Source: hint.source}
			summaries[hint.source] = summary
		}
		key := locationHintKey{kind: hint.kind, path: hint.path}
		if seenHints[key] {
			summary.Skipped++
			continue
		}
		seenHints[key] = true
		if budget == 0 {
			summary.Skipped++
			moreSkipped++
			continue
		}
		budget--
		checkedPath := hint.path
		if !rootInScope {
			checkedPath = container
		}
		ok, err := safeHintDir(checkedPath)
		if err != nil {
			reportIssue(checkedPath, err)
			summary.Skipped++
			continue
		}
		if !ok {
			if hint.configured {
				reportIssue(checkedPath, fmt.Errorf("configured location not found"))
			}
			summary.Skipped++
			continue
		}
		summary.Checked++
		if roots == nil && results.progress != nil {
			results.progress.Folders.Add(1)
		}
		switch hint.kind {
		case prefixHint:
			probePrefix(results, hint.path, roots, &budget, seenPrefixes, reportIssue, openDir)
		case rootHint:
			probePrefix(results, hint.path, roots, &budget, seenPrefixes, reportIssue, openDir)
			probeChildren(results, container, roots, &budget, seenPrefixes, seenContainers, reportIssue, openDir)
		case containerHint:
			probeChildren(results, hint.path, roots, &budget, seenPrefixes, seenContainers, reportIssue, openDir)
		}
	}
	if moreSkipped > 0 && roots == nil {
		reportIssue("known locations", fmt.Errorf("%d further location hints skipped after candidate limit", moreSkipped))
	}
	for _, summary := range summaries {
		results.report.Hints = append(results.report.Hints, *summary)
	}
}

type locationHintKey struct {
	kind hintKind
	path string
}

func probePrefix(results *condaResults, path string, roots []string, budget *int, seen map[string]bool, reportIssue func(string, error), openDir func(string) (*os.Root, error)) {
	ctx := results.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	if ctx.Err() != nil {
		return
	}
	if !inScope(path, roots) {
		return
	}
	if seen[path] {
		return
	}
	if *budget == 0 {
		reportIssue(path, fmt.Errorf("known-location limit of %d candidates reached", maxHintCandidates))
		return
	}
	seen[path] = true
	*budget = *budget - 1
	meta := filepath.Join(path, "conda-meta")
	ok, err := safeHintDir(meta)
	if err != nil {
		reportIssue(meta, err)
		return
	}
	if !ok {
		return
	}
	root, err := openDir(path)
	if err != nil {
		reportIssue(path, err)
		return
	}
	defer func() { _ = root.Close() }()
	env, valid, issues := inspectCondaPrefixRootOptions(ctx, root, path, !results.skipHistory)
	for _, problem := range issues {
		reportIssue(problem.Path, errors.New(problem.Error))
	}
	if valid {
		results.addEnvironment(env)
	}
}

func probeChildren(results *condaResults, container string, roots []string, budget *int, seenPrefixes, seenContainers map[string]bool, reportIssue func(string, error), openDir func(string) (*os.Root, error)) {
	if !inScope(container, roots) {
		return
	}
	if seenContainers[container] {
		return
	}
	seenContainers[container] = true
	ok, err := safeHintDir(container)
	if err != nil {
		reportIssue(container, err)
		return
	}
	if !ok {
		return
	}
	root, err := openDir(container)
	if err != nil {
		reportIssue(container, err)
		return
	}
	defer func() { _ = root.Close() }()
	f, err := root.Open(".")
	if err != nil {
		reportIssue(container, err)
		return
	}
	defer func() { _ = f.Close() }()
	entries, err := f.ReadDir(maxContainerEntries + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		reportIssue(container, err)
		return
	}
	if len(entries) > maxContainerEntries {
		reportIssue(container, fmt.Errorf("known-location container exceeds %d entries", maxContainerEntries))
		entries = entries[:maxContainerEntries]
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, entry := range entries {
		if entry.IsDir() {
			if *budget == 0 {
				reportIssue(container, fmt.Errorf("known-location limit of %d candidates reached", maxHintCandidates))
				return
			}
			probePrefix(results, filepath.Join(container, entry.Name()), roots, budget, seenPrefixes, reportIssue, openDir)
		}
	}
}
