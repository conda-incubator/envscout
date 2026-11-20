package evidence

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/conda-incubator/envscout/internal/discovery"
	"github.com/conda-incubator/envscout/internal/inventory"
)

func FileID(filename string) string {
	filename = filepath.ToSlash(filename)
	if !strings.HasPrefix(filename, "/") {
		filename = "/" + filename
	}
	return (&url.URL{Scheme: "file", Path: filename}).String()
}

// target points into the final validated slice; do not append while a view is in use.
// Prefix facts are immutable after validation.
type hostEnvironment struct {
	target  *Target
	prefix  Prefix
	request Request
}

// CollectHost requires explicit roots and never invokes an external tool.
// Without requested collectors it only lists the root targets. With collectors,
// discovery returns conda prefixes validated through inventory and marker-backed
// virtualenvs only when selected rules request virtualenv evidence.
func CollectHost(ctx context.Context, roots []string, req Request) (Snapshot, error) {
	snapshot := Snapshot{Started: time.Now().UTC(), Targets: []Target{}, Issues: []Issue{}, Inspection: &InspectionSummary{}}
	// Count observed access failures even when cancellation stops an attempt.
	defer func() {
		for _, target := range snapshot.Targets {
			for _, issue := range target.Issues {
				if issue.AccessDenied {
					snapshot.Inspection.AccessErrors++
				}
			}
		}
	}()
	if len(roots) == 0 {
		return snapshot, fmt.Errorf("lint requires explicit directory roots")
	}
	if err := ctx.Err(); err != nil {
		return snapshot, err
	}
	if len(req.Capabilities) == 0 && len(req.VirtualenvCapabilities) == 0 {
		seen := make(map[string]bool)
		for _, input := range roots {
			abs, err := filepath.Abs(input)
			if err != nil {
				return snapshot, err
			}
			info, err := os.Lstat(abs)
			if err != nil || !info.IsDir() {
				return snapshot, fmt.Errorf("lint root must be a real directory: %s", abs)
			}
			key := abs
			if runtime.GOOS == "windows" {
				key = strings.ToLower(key)
			}
			if seen[key] {
				continue
			}
			seen[key] = true
			snapshot.Targets = append(snapshot.Targets, Target{ID: FileID(abs), Kind: "dir", Input: abs, Roots: []string{abs}, Prefixes: []Prefix{}, Coverage: map[string]string{}, Issues: []Issue{}})
		}
		sort.Slice(snapshot.Targets, func(i, j int) bool { return snapshot.Targets[i].ID < snapshot.Targets[j].ID })
		return snapshot, nil
	}
	readHistory := Requested(req, CapHistory)
	report, discoveryErr := discovery.Find(ctx, roots, readHistory)
	snapshot.Inspection = &InspectionSummary{Found: len(report.Environments), DiscoveryIssues: len(report.Issues)}
	if errors.Is(discoveryErr, fs.ErrPermission) {
		snapshot.Inspection.AccessErrors++
	}
	progress := progressFrom(ctx)
	recorder := inspectionRecorder{summary: snapshot.Inspection, progress: progress}
	if progress != nil {
		progress.Total.Store(uint64(len(report.Environments)))
		progress.Started.Store(true)
	}
	for _, issue := range report.Issues {
		if issue.AccessDenied {
			snapshot.Inspection.AccessErrors++
		}
		capability := CapPrefixes
		if filepath.Base(issue.Path) == "history" {
			capability = CapHistory
		}
		snapshot.Issues = append(snapshot.Issues, Issue{Capability: capability, Path: issue.Path, Message: issue.Error, AccessDenied: issue.AccessDenied})
	}
	cancelErr := validateHostEnvironments(ctx, report, req, &snapshot, recorder)
	if cancelErr != nil {
		discoveryErr = errors.Join(discoveryErr, cancelErr)
	}
	envs, coverage := prepareHostEnvironments(&snapshot, req, readHistory, discoveryErr != nil || cancelErr != nil)
	// Project association uses the final validated list and runs once, only when the
	// collection finished without cancellation.
	if req.Project != "" && discoveryErr == nil && cancelErr == nil {
		if err := associateHostProject(ctx, &snapshot, envs, req, recorder); err != nil {
			return snapshot, err
		}
	}
	cancelErr = inspectHostEnvironments(ctx, envs, report.Issues, readHistory, recorder, cancelErr)
	if len(snapshot.Targets) == 0 && len(report.Roots) > 0 {
		snapshot.Targets = append(snapshot.Targets, Target{ID: FileID(report.Roots[0]), Kind: "dir", Input: report.Roots[0], Roots: report.Roots,
			Prefixes: []Prefix{}, Coverage: map[string]string{CapPrefixes: coverage}, Issues: []Issue{}})
		for _, capability := range req.Capabilities {
			snapshot.Targets[0].Coverage[capability] = coverage
		}
	}
	return snapshot, errors.Join(discoveryErr, cancelErr)
}

// Discovery candidates become targets only after canonical validation. Preserve
// accepted records on cancellation so later stages and every early return retain them.
func validateHostEnvironments(ctx context.Context, report discovery.Report, req Request, snapshot *Snapshot, recorder inspectionRecorder) error {
	var validated []Target
	var cancelErr error
	for _, env := range report.Environments {
		if err := ctx.Err(); err != nil {
			cancelErr = err
			break
		}
		// Venvs never enter conda validation or its cache and lock collectors.
		if env.Kind == discovery.KindVenv {
			if len(req.VirtualenvCapabilities) == 0 {
				snapshot.Issues = append(snapshot.Issues, Issue{Capability: "evaluation", Path: env.Path, Message: "virtualenv lint is not supported by the selected rules; use find or scan"})
				recorder.finish(true, time.Time{})
			} else {
				validated = append(validated, Target{ID: FileID(env.Path), Kind: "dir", Input: env.Path, Roots: report.Roots,
					Prefixes: []Prefix{{Kind: env.Kind, Path: env.Path, RecordCoverage: NotCollected}}, Coverage: map[string]string{}, Issues: []Issue{}})
			}
			continue
		}
		start := time.Now()
		recorder.begin(start)
		records, err := condaRecordsForPrefix(ctx, env.Path)
		recorder.end()
		if ctxErr := ctx.Err(); ctxErr != nil {
			cancelErr = ctxErr
		}
		if err != nil {
			snapshot.Issues = append(snapshot.Issues, Issue{Capability: CapPrefixes, Path: env.Path, Message: err.Error(), AccessDenied: errors.Is(err, fs.ErrPermission)})
			snapshot.Inspection.AccessErrors += accessErrorCount(err)
		}
		if len(records) == 0 {
			if cancelErr == nil {
				recorder.finish(true, time.Time{})
			}
			if err == nil {
				snapshot.Issues = append(snapshot.Issues, Issue{Capability: CapPrefixes, Path: env.Path, Message: "no valid conda package metadata; prefix not counted"})
			}
		} else {
			recordCoverage := Complete
			if err != nil {
				recordCoverage = Partial
			}
			tooling := false
			for _, record := range records {
				tooling = tooling || toolingName(record.Record.Name)
			}
			validated = append(validated, Target{ID: FileID(env.Path), Kind: "dir", Input: env.Path, Roots: report.Roots,
				Prefixes: []Prefix{{Kind: env.Kind, Path: env.Path, Revision: env.Revision, Tooling: tooling, Records: records, RecordCoverage: recordCoverage}}, Coverage: map[string]string{}, Issues: []Issue{}})
			if err != nil && Requested(req, CapCondaRecords) {
				hostIssue(&validated[len(validated)-1], CapCondaRecords, env.Path, "installed conda record collection is incomplete")
			}
		}
		if cancelErr != nil {
			break
		}
	}
	snapshot.Targets = validated
	return cancelErr
}

// Bind the final validated targets and their request scope before association or facts.
func prepareHostEnvironments(snapshot *Snapshot, req Request, readHistory, incomplete bool) ([]hostEnvironment, string) {
	coverage := Complete
	if incomplete {
		coverage = Partial
	}
	for _, issue := range snapshot.Issues {
		if issue.Capability == CapPrefixes {
			coverage = Partial
		}
	}
	historyCoverage := NotCollected
	if readHistory {
		historyCoverage = Complete
	}
	for _, issue := range snapshot.Issues {
		if issue.Capability == CapHistory {
			historyCoverage = Partial
		}
	}
	envs := make([]hostEnvironment, len(snapshot.Targets))
	for i := range snapshot.Targets {
		target := &snapshot.Targets[i]
		prefix := target.Prefixes[0]
		envs[i] = hostEnvironment{target: target, prefix: prefix, request: req.ForEnvironment(prefix.Kind)}
		targetReq := envs[i].request
		target.Coverage[CapPrefixes] = coverage
		target.Coverage[CapHistory] = historyCoverage
		if target.IsVirtualenv() {
			target.Coverage[CapHistory] = NotCollected
		}
		if readHistory && incomplete {
			target.Coverage[CapHistory] = Partial
		}
		if Requested(targetReq, CapProjectAssociation) {
			target.Coverage[CapProjectAssociation] = Complete
		}
		target.initCoverage(targetReq, []string{CapCondaRecords, CapPythonDistributions, CapHostCache, CapInstalledLock})
		if Requested(targetReq, CapCondaRecords) {
			target.Coverage[CapCondaRecords] = prefix.RecordCoverage
		}
	}
	return envs, coverage
}

func associateHostProject(ctx context.Context, snapshot *Snapshot, envs []hostEnvironment, req Request, recorder inspectionRecorder) error {
	var projectTarget *Target
	prefixCount := 0
	for _, env := range envs {
		if env.prefix.Kind != discovery.KindVenv {
			projectTarget = env.target
			prefixCount++
		}
	}
	if prefixCount != 1 {
		return errors.Join(nil, fmt.Errorf("--project requires exactly one validated prefix for an explicit association"))
	}
	if Requested(req, CapProjectAssociation) {
		project, issue, err := collectProjectContext(ctx, req.Project)
		if err != nil {
			snapshot.Inspection.AccessErrors += accessErrorCount(err)
			if ctx.Err() == nil {
				recorder.finish(true, time.Time{})
			}
			return err
		}
		target := projectTarget
		target.Project = project
		if issue != nil {
			target.Issues = append(target.Issues, *issue)
			target.Coverage[CapProjectAssociation] = Partial
		}
	}
	return nil
}

func inspectHostEnvironments(ctx context.Context, envs []hostEnvironment, issues []discovery.Issue, readHistory bool, recorder inspectionRecorder, cancelErr error) error {
	caches := map[string]Target{}
	for _, env := range envs {
		target := env.target
		if cancelErr != nil || ctx.Err() != nil {
			target.markCollectedPartial()
			continue
		}
		start := time.Now()
		recorder.begin(start)
		if err := env.collectFacts(ctx, caches); err != nil {
			cancelErr = errors.Join(cancelErr, err)
		}
		if ctx.Err() != nil {
			recorder.end()
			continue
		}
		failed := len(target.Issues) != 0 || env.prefix.RecordCoverage == Partial
		for _, issue := range issues {
			if issue.Path == filepath.Join(target.Input, "conda-meta", "history") && readHistory {
				failed = true
			}
		}
		recorder.finish(failed, start)
	}
	return cancelErr
}

func accessErrorCount(err error) int {
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		count := 0
		for _, cause := range joined.Unwrap() {
			count += accessErrorCount(cause)
		}
		return count
	}
	if cause := errors.Unwrap(err); cause != nil {
		return accessErrorCount(cause)
	}
	if errors.Is(err, fs.ErrPermission) {
		return 1
	}
	return 0
}

// The bounded direct metadata index never visits nested environments or follows
// links. Inventory parses original record bytes; this layer owns the filesystem.
func condaRecordsForPrefix(ctx context.Context, prefix string) ([]inventory.CondaRecord, error) {
	root, err := os.OpenRoot(prefix)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	info, err := hostLstat(root, "conda-meta")
	if err != nil || !info.IsDir() {
		return nil, fmt.Errorf("conda-meta is not a real directory")
	}
	dir, err := root.Open("conda-meta")
	if err != nil {
		return nil, err
	}
	entries, enumerationErr := dir.ReadDir(hostEntryLimit + 1)
	_ = dir.Close()
	if errors.Is(enumerationErr, io.EOF) {
		enumerationErr = nil
	}
	if len(entries) > hostEntryLimit {
		entries = entries[:hostEntryLimit]
		enumerationErr = errors.Join(enumerationErr, fmt.Errorf("conda-meta entry limit exceeded (%d)", hostEntryLimit))
	}
	files := make(map[string]os.FileInfo)
	var paths []string
	for _, entry := range entries {
		if ctx.Err() != nil {
			break
		}
		if filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		if entry.Type()&os.ModeSymlink != 0 {
			enumerationErr = errors.Join(enumerationErr, fmt.Errorf("linked conda record %s is not followed", filepath.Join(prefix, "conda-meta", entry.Name())))
			continue
		}
		info, err := entry.Info()
		if err != nil {
			enumerationErr = errors.Join(enumerationErr, fmt.Errorf("conda record metadata unavailable"))
			continue
		}
		name := filepath.Join("conda-meta", entry.Name())
		files[name] = info
		paths = append(paths, name)
	}
	sort.Strings(paths)
	if err := ctx.Err(); err != nil {
		return nil, errors.Join(err, enumerationErr, ctx.Err())
	}
	// Keep the former resolver's cancellation boundary before reading any records.
	var names []string
	for _, name := range paths {
		if ctx.Err() != nil {
			break
		}
		if files[name].Mode().IsRegular() {
			names = append(names, name)
		}
	}
	var records []inventory.CondaRecord
	var readBytes int64
	err = ctx.Err()
	for index, name := range names {
		if ctx.Err() != nil {
			break
		}
		filename := filepath.Join(prefix, name)
		record, readErr := readHostCondaRecord(ctx, root, name, filename, files[name], &readBytes)
		if readErr != nil {
			err = errors.Join(err, fmt.Errorf("conda record %s: %w", filename, readErr))
			continue
		}
		record.Path, record.Record.SourcePath = filename, filename
		record.Record.SourceIndex = index
		records = append(records, record)
	}
	return records, errors.Join(errors.Join(err, ctx.Err()), enumerationErr, ctx.Err())
}

func readHostCondaRecord(ctx context.Context, root *os.Root, name, filename string, info os.FileInfo, readBytes *int64) (inventory.CondaRecord, error) {
	// Match inventory's direct-document guard, including Unix backslash names.
	real := strings.ReplaceAll(filename, "\\", "/")
	if path.Base(path.Dir(real)) != "conda-meta" || path.Ext(real) != ".json" {
		return inventory.CondaRecord{}, fmt.Errorf("metadata is not a direct conda-meta document")
	}
	if !info.Mode().IsRegular() || info.Size() < 0 {
		return inventory.CondaRecord{}, fmt.Errorf("metadata is not a regular file")
	}
	if info.Size() > inventory.CondaRecordByteLimit {
		return inventory.CondaRecord{}, fmt.Errorf("metadata exceeds %d bytes", inventory.CondaRecordByteLimit)
	}
	if *readBytes+info.Size() > 256<<20 {
		return inventory.CondaRecord{}, fmt.Errorf("host metadata read limit exceeded")
	}
	// Failed reads still consume the indexed size, as in the former resolver.
	*readBytes += info.Size()
	data, err := readHostMetadata(ctx, root, name, inventory.CondaRecordByteLimit)
	if err != nil {
		return inventory.CondaRecord{}, err
	}
	// Preserve the old context-checked buffer read before invoking the parser.
	data, err = io.ReadAll(io.LimitReader(evidenceContextReader{ctx, bytes.NewReader(data)}, inventory.CondaRecordByteLimit+1))
	if err != nil {
		return inventory.CondaRecord{}, err
	}
	return inventory.ParseCondaRecord(data)
}

// The association is supplied by the caller. Presence of a lock is not proof of
// manifest or installation synchronization; those require separate verifiers.
func collectProjectContext(ctx context.Context, input string) (*Project, *Issue, error) {
	abs, err := filepath.Abs(input)
	if err != nil {
		return nil, nil, err
	}
	info, err := os.Lstat(abs)
	if err != nil {
		return nil, nil, fmt.Errorf("--project must name a real directory: %w", err)
	}
	if !info.IsDir() {
		return nil, nil, fmt.Errorf("--project must name a real directory")
	}
	// os.OpenRoot confines every lock lookup to the project directory, so a lock
	// name that is a symlink or points outside it can never be read.
	root, err := os.OpenRoot(abs)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = root.Close() }()
	p := &Project{Path: abs, Associated: true, Reason: "explicit user association; no resolved lock found"}
	for _, name := range []string{"pixi.lock", "conda-lock.yaml", "conda-lock.yml", "uv.lock", "poetry.lock", "Pipfile.lock"} {
		info, err := root.Lstat(name)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil || !info.Mode().IsRegular() || info.Size() > 1<<20 || info.Size() == 0 {
			return p, &Issue{Capability: CapProjectAssociation, Path: filepath.Join(abs, name), Message: "lock candidate is inaccessible, empty, linked or oversized", AccessDenied: errors.Is(err, fs.ErrPermission)}, nil
		}
		if name == "pixi.lock" {
			data, err := readHostMetadata(ctx, root, name, 1<<20)
			if err != nil || validatePixiLock(data) != nil {
				return p, &Issue{Capability: CapProjectAssociation, Path: filepath.Join(abs, name), Message: "Pixi lock could not be parsed; lock presence is unknown", AccessDenied: errors.Is(err, fs.ErrPermission)}, ctx.Err()
			}
		}
		p.LockPath = filepath.Join(abs, name)
		p.Reason = "regular lock presence only; installed metadata and manifest synchronization not verified"
		if name == "pixi.lock" {
			p.Reason = "parsed Pixi lock presence only; installed metadata and manifest synchronization not verified"
		} else {
			p.Reason += "; format parser unavailable"
		}
		return p, nil, nil
	}
	return p, nil, nil
}
