package discovery

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

// inspectScopedPrefix confirms a prefix from its conda-meta directory. The scope root is
// the prefix itself; all reads go through it. A prefix is a candidate when conda-meta is
// a real directory holding at least one regular .json entry. Record contents are not
// decoded here; that validation belongs to inventory/lint.
func inspectScopedPrefix(ctx context.Context, scope *os.Root, prefix string, readHistory bool) (Environment, bool, []Issue) {
	var issues []Issue
	metaPath := filepath.Join(prefix, "conda-meta")
	meta, err := scope.Lstat("conda-meta")
	if err != nil {
		return Environment{}, false, append(issues, Issue{Path: metaPath, Error: err.Error()})
	}
	if !meta.IsDir() {
		return Environment{}, false, append(issues, Issue{Path: metaPath, Error: "conda-meta is not a directory"})
	}
	metaRoot, err := scope.OpenRoot("conda-meta")
	if err != nil {
		return Environment{}, false, append(issues, Issue{Path: metaPath, Error: err.Error()})
	}
	defer func() { _ = metaRoot.Close() }()

	hasRecord, truncated, err := hasRecordEntry(ctx, metaRoot)
	if err != nil {
		return Environment{}, false, append(issues, Issue{Path: metaPath, Error: err.Error()})
	}
	if truncated {
		issues = append(issues, Issue{Path: metaPath, Error: fmt.Sprintf("conda-meta exceeds %d entries; record scan truncated", maxRecordsPerPrefix)})
	}
	if !hasRecord {
		return Environment{}, false, issues
	}
	env := Environment{Name: filepath.Base(prefix), Path: prefix}
	if !readHistory {
		return env, true, issues
	}
	rev, err := readRevision(ctx, metaRoot, "history")
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		issues = append(issues, Issue{Path: filepath.Join(metaPath, "history"), Error: err.Error()})
	}
	env.Revision = rev
	return env, true, issues
}

// hasRecordEntry reports whether conda-meta holds a regular .json file. The first match
// ends the search. truncated is set when the listing exceeded the entry bound.
func hasRecordEntry(ctx context.Context, metaRoot *os.Root) (found, truncated bool, err error) {
	dir, err := metaRoot.Open(".")
	if err != nil {
		return false, false, err
	}
	defer func() { _ = dir.Close() }()
	entries, err := dir.ReadDir(maxRecordsPerPrefix + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return false, false, err
	}
	if len(entries) > maxRecordsPerPrefix {
		entries = entries[:maxRecordsPerPrefix]
		truncated = true
	}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return false, truncated, err
		}
		if recordIsCandidate(entry.Name()) && entry.Type().IsRegular() {
			return true, truncated, nil
		}
	}
	return false, truncated, nil
}

// readRevision reads conda-meta/history. The entry is Lstat'ed inside the scope first: a
// symlink or any non-regular entry, and any file over the byte bound, is an error and
// yields no revision. Only then is it opened and read through the bounded reader.
func readRevision(ctx context.Context, metaRoot *os.Root, name string) (*int, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	info, err := metaRoot.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("history is not a regular file")
	}
	if info.Size() > maxHistoryBytes {
		return nil, fmt.Errorf("history exceeds %d bytes", maxHistoryBytes)
	}
	file, err := metaRoot.Open(name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	return boundedHistoryRevision(ctx, file)
}
