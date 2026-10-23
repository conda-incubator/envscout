package evidence

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/anaconda/envscout/internal/imageinput"
)

// Collect gathers evidence for one source. It performs no signal handling,
// output, or timeout policy: the caller supplies ctx and owns cancellation.
//
// Source "dir" accepts one or more explicit roots. Source "oci-archive" accepts
// exactly one archive path together with the platform OS/ARCH[/VARIANT].
//
// On error the returned snapshot still carries any partial targets and issues,
// plus a source issue describing the failure so that a report renders as
// incomplete rather than silently clean.
func Collect(ctx context.Context, source string, inputs []string, platform string, req Request) (Snapshot, error) {
	var snapshot Snapshot
	var err error
	switch source {
	case "dir":
		snapshot, err = CollectHost(ctx, inputs, req, nil)
	case "oci-archive":
		if len(inputs) != 1 {
			err = fmt.Errorf("oci-archive source requires exactly one archive input, got %d", len(inputs))
			snapshot = emptySnapshot()
		} else {
			snapshot, err = collectArchive(ctx, inputs[0], platform, req)
		}
	default:
		err = fmt.Errorf("unsupported evidence source %q", source)
		snapshot = emptySnapshot()
	}
	if snapshot.Started.IsZero() {
		snapshot.Started = time.Now().UTC()
	}
	if snapshot.Targets == nil {
		snapshot.Targets = []Target{}
	}
	if snapshot.Issues == nil {
		snapshot.Issues = []Issue{}
	}
	// Some collectors return a nil error on a context that expired after their
	// last check. Treat that as incomplete, not as a clean result.
	if err == nil {
		err = ctx.Err()
	}
	if err != nil {
		snapshot.Issues = append(snapshot.Issues, Issue{Capability: "source", Path: source, Message: err.Error()})
	}
	return snapshot, err
}

func emptySnapshot() Snapshot {
	return Snapshot{Started: time.Now().UTC(), Targets: []Target{}, Issues: []Issue{}}
}

// collectArchive loads one OCI archive, always releases its staged layout, and
// keeps partial image evidence alongside any collection or cleanup error.
func collectArchive(ctx context.Context, input, platform string, req Request) (Snapshot, error) {
	snapshot := emptySnapshot()
	if err := ctx.Err(); err != nil {
		return snapshot, err
	}
	loaded, err := imageinput.Load(ctx, input, platform)
	if err != nil {
		return snapshot, err
	}
	target, err := CollectImage(ctx, loaded, req)
	if target.ID != "" {
		snapshot.Targets = append(snapshot.Targets, target)
	}
	return snapshot, errors.Join(err, loaded.Close())
}
