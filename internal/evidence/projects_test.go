package evidence

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProjectLockPresenceWithoutSync(t *testing.T) {
	for _, name := range []string{"pixi.lock", "conda-lock.yaml", "uv.lock"} {
		t.Run(name, func(t *testing.T) {
			project := t.TempDir()
			contents := "presence only, no supported verifier"
			if name == "pixi.lock" {
				contents = hostPixiLock
			}
			hostWrite(t, filepath.Join(project, name), contents)
			p, issue, err := collectProject(project)
			if err != nil || issue != nil || p.LockPath != filepath.Join(project, name) || !strings.Contains(p.Reason, "presence") {
				t.Fatalf("lock presence = %+v %+v %v", p, issue, err)
			}
		})
	}
}

func TestProjectMalformedPixiLockIsUnknown(t *testing.T) {
	project := t.TempDir()
	hostWrite(t, filepath.Join(project, "pixi.lock"), "version: 4\nenvironments: [malformed\n")
	p, issue, err := collectProject(project)
	if err != nil || issue == nil || p.LockPath != "" {
		t.Fatalf("malformed Pixi lock accepted: %+v %+v %v", p, issue, err)
	}
}

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
