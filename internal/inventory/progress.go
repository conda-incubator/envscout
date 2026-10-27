package inventory

import (
	"context"
	"sync/atomic"
)

// Progress contains display counters only; it does not change scan scheduling.
// Finished includes failed and pre-existing attempts, counted separately below.
type Progress struct {
	Started         atomic.Bool
	Total           atomic.Uint64
	Active          atomic.Uint64
	Finished        atomic.Uint64
	Failed          atomic.Uint64
	PreExisting     atomic.Uint64
	Cataloged       atomic.Uint64
	CatalogDuration atomic.Int64 // Nanoseconds spent on successful, newly written SBOMs.
	ActiveStarted   atomic.Int64 // Unix nanoseconds; display-only active attempt start.
}

type progressKey struct{}

// WithProgress attaches optional counters. Disabled renderers leave ctx unchanged.
func WithProgress(ctx context.Context, progress *Progress) context.Context {
	if progress == nil {
		return ctx
	}
	return context.WithValue(ctx, progressKey{}, progress)
}

func progressFrom(ctx context.Context) *Progress {
	progress, _ := ctx.Value(progressKey{}).(*Progress)
	return progress
}
