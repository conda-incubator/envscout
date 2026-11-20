package discovery

import (
	"context"
	"fmt"
	"io"
	"strings"
)

const (
	maxMetadataBytes = 1 << 20
	maxHistoryBytes  = 16 << 20
	// maxRecordsPerPrefix bounds how many conda-meta entries are enumerated per
	// prefix; beyond this the prefix is still reported but with an explicit issue.
	maxRecordsPerPrefix = 10000
)

// recordIsCandidate reports whether a conda-meta entry name looks like a package
// record. Content is deliberately not decoded here; validation belongs to inventory/lint.
func recordIsCandidate(name string) bool {
	return strings.HasSuffix(name, ".json")
}

// boundedHistoryRevision reads at most maxHistoryBytes. The byte bound is enforced
// on the reader itself, so a file that grows after stat cannot escape the limit.
func boundedHistoryRevision(ctx context.Context, r io.Reader) (*int, error) {
	limited := &io.LimitedReader{R: r, N: maxHistoryBytes + 1}
	rev, err := parseHistoryRevision(contextReader{ctx: ctx, r: limited})
	if err != nil {
		return nil, err
	}
	if limited.N == 0 {
		return nil, fmt.Errorf("history exceeds %d bytes", maxHistoryBytes)
	}
	return rev, nil
}

// contextReader checks cancellation before each read. io offers no context, so this
// is the only point at which a caller's cancellation can be honored mid-read.
type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (c contextReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}
