package discovery

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"sort"

	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/filetree"
	"github.com/anchore/stereoscope/pkg/image"
)

// Image source and scope describe what was searched: the final squashed filesystem of an
// OCI archive. Host hints never apply to an image.
const (
	imageSource        = "oci-archive"
	imageScope         = "squashed"
	imageSchemaVersion = 1
)

// FindImage searches the final squashed filesystem of img using image POSIX paths only.
// The image must already be read. Cancellation returns the context error; unreadable
// evidence and links are reported as Issues. readHistory controls history parsing.
func FindImage(ctx context.Context, img *image.Image, readHistory bool) (report Report, err error) {
	report = newReport(ModeImage)
	report.Source = imageSource
	report.Scope = imageScope
	report.SchemaVersion = imageSchemaVersion
	defer sortReport(&report)
	if err := ctx.Err(); err != nil {
		return report, err
	}
	if img == nil {
		return report, fmt.Errorf("image is required")
	}
	if len(img.Layers) > 0 && img.Layers[len(img.Layers)-1] == nil {
		return report, fmt.Errorf("image has no final layer")
	}
	tree := img.SquashedTree()
	if tree == nil || img.FileCatalog == nil {
		return report, fmt.Errorf("image must be read before discovery")
	}
	searcher := img.SquashedSearchContext
	if searcher == nil {
		searcher = filetree.NewSearchContext(tree, img.FileCatalog)
	}

	// SearchByGlob applies whiteouts and opaque directories. The library takes no context,
	// so cancellation is checked before and after the call and while consuming results.
	refs, searchErr := searcher.SearchByGlob("**/conda-meta/*.json")
	if err := ctx.Err(); err != nil {
		return report, err
	}
	if searchErr != nil {
		report.Issues = append(report.Issues, Issue{Path: "/", Error: fmt.Sprintf("search image squash: %v", searchErr)})
	}

	prefixes := make(map[string]bool)
	for _, res := range refs {
		if err := ctx.Err(); err != nil {
			return report, err
		}
		report.MetadataFilesExamined++
		requested := string(res.RequestPath)
		if !isRegularImageRecord(img, res) {
			report.Issues = append(report.Issues, Issue{Path: requested, Error: "record is absent, not a regular file, or reached through a link; links are not followed"})
			continue
		}
		prefixes[path.Dir(path.Dir(requested))] = true
	}

	// Iterate prefixes in sorted order so a cancelled run retains a deterministic subset.
	ordered := make([]string, 0, len(prefixes))
	for prefixPath := range prefixes {
		ordered = append(ordered, prefixPath)
	}
	sort.Strings(ordered)
	for _, prefixPath := range ordered {
		if err := ctx.Err(); err != nil {
			return report, err
		}
		env := Environment{Name: path.Base(prefixPath), Path: prefixPath, Kind: KindConda}
		if readHistory {
			histPath := path.Join(prefixPath, "conda-meta", "history")
			rev, herr := imageRevision(ctx, img, searcher, histPath)
			if err := ctx.Err(); err != nil {
				return report, err
			}
			if herr != nil && !errors.Is(herr, fs.ErrNotExist) {
				report.Issues = append(report.Issues, Issue{Path: histPath, Error: herr.Error()})
			}
			env.Revision = rev
		}
		report.Environments = append(report.Environments, env)
	}
	return report, ctx.Err()
}

// isRegularImageRecord reports whether a glob match is a direct, non-link regular file.
// The reference must exist, RequestPath must equal RealPath (no link traversal), and the
// catalog entry must be of regular type. Size is irrelevant at discovery time.
func isRegularImageRecord(img *image.Image, res file.Resolution) bool {
	if res.Reference == nil || string(res.RealPath) != string(res.RequestPath) {
		return false
	}
	entry, err := img.FileCatalog.Get(*res.Reference)
	return err == nil && entry.Type == file.TypeRegular
}

// imageRevision reads a squashed history under the same byte bound as host history.
// A missing or link-resolved history yields no revision; links are never followed.
func imageRevision(ctx context.Context, img *image.Image, searcher filetree.Searcher, name string) (*int, error) {
	res, err := searcher.SearchByPath(name)
	if err != nil {
		return nil, err
	}
	if res == nil || res.Reference == nil {
		return nil, fs.ErrNotExist
	}
	if string(res.RealPath) != name {
		return nil, fmt.Errorf("history reached through a link; links are not followed")
	}
	entry, err := img.FileCatalog.Get(*res.Reference)
	if err != nil {
		return nil, err
	}
	if entry.Type != file.TypeRegular {
		return nil, fmt.Errorf("history is not a regular file")
	}
	if entry.Size() < 0 || entry.Size() > maxHistoryBytes {
		return nil, fmt.Errorf("history exceeds %d bytes", maxHistoryBytes)
	}
	reader, err := img.OpenReference(*res.Reference)
	if err != nil {
		return nil, err
	}
	defer func() { _ = reader.Close() }()
	return boundedHistoryRevision(ctx, io.Reader(reader))
}
