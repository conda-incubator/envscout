package inventory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"slices"
	"strings"

	stereofile "github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/source"
	gorattler "github.com/conda-incubator/go-rattler"
)

const (
	// CondaRecordByteLimit bounds one installed-record document. Real records can list tens of
	// thousands of files, so the bound allows that without letting one file exhaust memory.
	CondaRecordByteLimit = 32 << 20
	condaRecordLimit     = 10000
)

// CondaRecord retains a canonical installed package and the source-qualified path
// of its conda-meta document. Record paths and URLs are metadata, not host paths.
type CondaRecord struct {
	Path   string
	Record gorattler.PrefixRecord
	// OwnershipKnown distinguishes explicit file lists (including empty lists)
	// from metadata that omitted ownership information.
	OwnershipKnown bool
}

// CondaRecords reads direct regular conda-meta documents through src's resolver
// and parses their original bytes with rattler. It borrows src and never closes it.
// Reads are limited to CondaRecordByteLimit per record and 10,000 records. Successful records
// survive other read/parse failures and cancellation; any failure means coverage
// is incomplete. Results are sorted by source path, not package identity.
func CondaRecords(ctx context.Context, src source.Source, scope source.Scope) ([]CondaRecord, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	resolver, err := src.FileResolver(scope)
	if err != nil {
		return nil, fmt.Errorf("resolve conda records: %w", err)
	}
	locations, searchErr := resolver.FilesByGlob("**/conda-meta/*.json")
	slices.SortFunc(locations, func(a, b file.Location) int { return strings.Compare(a.RealPath, b.RealPath) })
	var records []CondaRecord
	err = searchErr
	for index, location := range locations {
		if ctx.Err() != nil {
			break
		}
		if index >= condaRecordLimit {
			err = errors.Join(err, fmt.Errorf("conda record limit exceeded (%d)", condaRecordLimit))
			break
		}
		record, readErr := readCondaRecord(ctx, resolver, location)
		if readErr != nil {
			err = errors.Join(err, fmt.Errorf("conda record %s: %w", location.Path(), readErr))
			continue
		}
		record.Record.SourceIndex, record.Record.SourcePath = index, location.RealPath
		records = append(records, record)
	}
	return records, errors.Join(err, ctx.Err())
}

func readCondaRecord(ctx context.Context, resolver file.Resolver, location file.Location) (CondaRecord, error) {
	real := strings.ReplaceAll(location.RealPath, "\\", "/")
	if location.RealPath != location.AccessPath || path.Base(path.Dir(real)) != "conda-meta" || path.Ext(real) != ".json" {
		return CondaRecord{}, fmt.Errorf("metadata is not a direct conda-meta document")
	}
	metadata, err := resolver.FileMetadataByLocation(location)
	if err != nil {
		return CondaRecord{}, err
	}
	if metadata.FileInfo == nil || metadata.Type != stereofile.TypeRegular || !metadata.Mode().IsRegular() || metadata.Size() < 0 {
		return CondaRecord{}, fmt.Errorf("metadata is not a regular file")
	}
	if metadata.Size() > CondaRecordByteLimit {
		return CondaRecord{}, fmt.Errorf("metadata exceeds %d bytes", CondaRecordByteLimit)
	}
	reader, err := resolver.FileContentsByLocation(location)
	if err != nil {
		return CondaRecord{}, err
	}
	data, readErr := io.ReadAll(io.LimitReader(recordContextReader{ctx, reader}, CondaRecordByteLimit+1))
	if err := errors.Join(readErr, reader.Close()); err != nil {
		return CondaRecord{}, err
	}
	if len(data) > CondaRecordByteLimit {
		return CondaRecord{}, fmt.Errorf("metadata exceeds %d bytes", CondaRecordByteLimit)
	}
	// Parse bytes already read even if cancellation arrived on their last read.
	// The caller keeps this positive and returns the context error alongside it.
	record, err := gorattler.ParsePrefixRecord(data)
	if err != nil {
		return CondaRecord{}, err
	}
	// Canonical parsing supplies values but defaults omitted ownership lists to
	// empty. Inspect exact raw keys only to retain whether a list was provided.
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return CondaRecord{}, err
	}
	known := len(fields["files"]) > 0 && string(fields["files"]) != "null"
	if !known && len(fields["paths_data"]) > 0 && string(fields["paths_data"]) != "null" {
		var paths map[string]json.RawMessage
		if err := json.Unmarshal(fields["paths_data"], &paths); err != nil {
			return CondaRecord{}, err
		}
		known = len(paths["paths"]) > 0 && string(paths["paths"]) != "null"
	}
	return CondaRecord{Path: location.RealPath, Record: record, OwnershipKnown: known}, nil
}

type recordContextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r recordContextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}
