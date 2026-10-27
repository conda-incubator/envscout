package inventory

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/anchore/syft/syft/source/directorysource"
)

// Syft's Base rebases paths but does not confine drive-qualified Windows links.
// Exclude escaping links before its indexer can add their targets as scan roots.
func virtualenvSourceConfig(ctx context.Context, prefix string) (directorysource.Config, error) {
	if err := ctx.Err(); err != nil {
		return directorysource.Config{}, err
	}
	root, err := filepath.EvalSymlinks(prefix)
	if err != nil {
		return directorysource.Config{}, err
	}
	root, err = filepath.Abs(root)
	if err != nil {
		return directorysource.Config{}, err
	}
	config := directorysource.Config{Path: root, Base: root}
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink == 0 {
			return nil
		}
		target, err := filepath.EvalSymlinks(path)
		if err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("resolve virtualenv link %s: %w", path, err)
		}
		if err == nil {
			if relative, err := filepath.Rel(root, target); err == nil && filepath.IsLocal(relative) {
				return nil
			}
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		// Syft exclusions are glob patterns; quote link names as literal paths.
		literal := strings.NewReplacer("\\", "\\\\", "*", "\\*", "?", "\\?", "[", "\\[", "]", "\\]", "{", "\\{", "}", "\\}").Replace(filepath.ToSlash(relative))
		config.Exclude.Paths = append(config.Exclude.Paths, "./"+literal)
		return nil
	})
	return config, err
}
