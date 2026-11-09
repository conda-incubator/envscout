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

// inspectionRecorder pairs host summary counts with optional live progress.
// Validation can be active without finishing an attempt or adding a timing sample.
type inspectionRecorder struct {
	summary  *InspectionSummary
	progress *Progress
}

func (r inspectionRecorder) begin(start time.Time) {
	if r.progress != nil {
		r.progress.ActiveStarted.Store(start.UnixNano())
		r.progress.Active.Store(1)
	}
}

func (r inspectionRecorder) end() {
	if r.progress != nil {
		r.progress.Active.Store(0)
		r.progress.ActiveStarted.Store(0)
	}
}

func (r inspectionRecorder) finish(failed bool, start time.Time) {
	if failed {
		r.summary.Failed++
	} else {
		r.summary.Inspected++
	}
	var duration time.Duration
	if !start.IsZero() {
		duration = time.Since(start)
	}
	r.progress.finish(failed, duration)
}
