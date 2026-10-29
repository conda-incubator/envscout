package discovery

import (
	"context"
	"fmt"
	"path"
	"path/filepath"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
)

type exclusionsKey struct{}

// WithExclusions validates discovery-only folder globs once for all consumers.
// Bare names match at any depth; other relative patterns are search-root relative.
// Matches are case-sensitive, including on Windows.
func WithExclusions(ctx context.Context, patterns []string) (context.Context, error) {
	if len(patterns) == 0 {
		return ctx, nil
	}
	normalized := make([]string, 0, len(patterns))
	for _, pattern := range patterns {
		p := filepath.ToSlash(pattern)
		p = strings.TrimPrefix(p, "./")
		if p != "/" {
			p = strings.TrimSuffix(p, "/")
		}
		if p == "" || !doublestar.ValidatePattern(p) {
			return ctx, fmt.Errorf("invalid --exclude glob %q", pattern)
		}
		normalized = append(normalized, p)
	}
	return context.WithValue(ctx, exclusionsKey{}, normalized), nil
}

func excluded(ctx context.Context, root, name string, otherRoots ...string) bool {
	patterns, _ := ctx.Value(exclusionsKey{}).([]string)
	if len(patterns) == 0 {
		return false
	}
	for _, otherRoot := range otherRoots {
		if excluded(ctx, otherRoot, name) {
			return true
		}
	}
	root = path.Clean(filepath.ToSlash(root))
	rootPrefix := strings.TrimSuffix(root, "/") + "/"
	name = path.Clean(filepath.ToSlash(name))
	// Direct hints and nested explicit roots must also honor excluded ancestors.
	for current := name; ; current = path.Dir(current) {
		for _, pattern := range patterns {
			candidate := current
			switch {
			case strings.HasPrefix(pattern, "/") || filepath.VolumeName(filepath.FromSlash(pattern)) != "":
			case !strings.Contains(pattern, "/"):
				candidate = path.Base(current)
				if pattern == "." && current == root {
					candidate = "."
				}
			default:
				if current == root {
					candidate = "."
				} else if strings.HasPrefix(current, rootPrefix) {
					candidate = strings.TrimPrefix(current, rootPrefix)
				} else {
					continue
				}
			}
			if doublestar.MatchUnvalidated(pattern, candidate) {
				return true
			}
		}
		if current == path.Dir(current) {
			return false
		}
	}
}
