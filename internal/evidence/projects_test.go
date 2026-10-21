package evidence

import (
	"os"
	"path/filepath"
	"testing"
)

func TestProjectRejectsSymlinkLock(t *testing.T) {
	project, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside.lock")
	if err := os.WriteFile(outside, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(project, "pixi.lock")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	_, issue, err := collectProject(project)
	if err != nil || issue == nil {
		t.Fatalf("symlink lock accepted: %+v %v", issue, err)
	}
}

func TestFileIdentityEscapesControlCharacters(t *testing.T) {
	id := FileID("/tmp/env\nname")
	if id != "file:///tmp/env%0Aname" {
		t.Fatalf("unsafe identity %q", id)
	}
}
