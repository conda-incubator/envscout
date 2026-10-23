package discovery

import (
	"context"
	"sync/atomic"
)

// Progress holds live counters for a discovery run. Folders counts directories examined
// by the walkers and probers, including repeat visits and nested roots; Environments counts
// unique environments by path. Counters are additive across Find calls sharing one context.
// The zero value is ready to use and safe for concurrent reads while a walk is running.
type Progress struct {
	Folders      atomic.Uint64
	Environments atomic.Uint64
}

type progressKey struct{}

// WithProgress returns a context that makes Find and FindKnown update progress. A nil
// progress returns ctx unchanged, so disabled instrumentation adds no context layer.
func WithProgress(ctx context.Context, progress *Progress) context.Context {
	if progress == nil {
		return ctx
	}
	return context.WithValue(ctx, progressKey{}, progress)
}

// progressFrom returns the Progress attached by WithProgress, or nil when none is set.
func progressFrom(ctx context.Context) *Progress {
	p, _ := ctx.Value(progressKey{}).(*Progress)
	return p
}
