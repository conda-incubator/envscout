package lint

import (
	"time"

	"github.com/conda-incubator/envscout/internal/evidence"
)

// Evaluation inputs belong to lint, not to the immutable collected evidence.
type evaluationContext struct {
	now   time.Time
	peers []evidence.Prefix
}
