package evidence

import (
	"context"
	"sync/atomic"
	"time"
)

// Progress counts completed local evidence collection attempts, not rule findings.
type Progress struct {
	Started            atomic.Bool
	Total              atomic.Uint64
	Finished           atomic.Uint64
	Failed             atomic.Uint64
	Active             atomic.Uint64
	Inspected          atomic.Uint64
	InspectionDuration atomic.Int64 // Successful evidence passes; prior validation is excluded.
	ActiveStarted      atomic.Int64 // Unix nanoseconds; current collection step only.
}

type progressKey struct{}

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

func (p *Progress) finish(failed bool, duration time.Duration) {
	if p != nil {
		if failed {
			p.Failed.Add(1)
		} else {
			p.InspectionDuration.Add(int64(duration))
			p.Inspected.Add(1)
		}
		p.Finished.Add(1)
		p.Active.Store(0)
		p.ActiveStarted.Store(0)
	}
}
