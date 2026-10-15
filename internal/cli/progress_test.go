package cli

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestStatusRedirected(t *testing.T) {
	var output bytes.Buffer
	if status := startStatus(&output, func() string { return "Folders: 1  Envs: 0" }); status != nil {
		t.Fatal("redirected output must not show a status")
	}
	if output.Len() != 0 {
		t.Fatalf("unexpected output: %q", output.String())
	}
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = read.Close() }()
	defer func() { _ = write.Close() }()
	if status := startStatus(write, func() string { return "Folders: 1  Envs: 0" }); status != nil {
		status.close()
		t.Fatal("a pipe must not be mistaken for a terminal")
	}
}

func TestStatusDrawAndClear(t *testing.T) {
	var output bytes.Buffer
	status := &statusLine{writer: &output, width: 12, stop: make(chan struct{}), done: make(chan struct{})}
	close(status.done)
	status.draw("Folders: 12345  Envs: 1")
	status.close()
	if got := output.String(); got != "\r\x1b[2KFolders: 12\r\x1b[2K" {
		t.Fatalf("unexpected status or clear sequence: %q", got)
	}
	if strings.Contains(output.String(), "\n") {
		t.Fatal("transient status must not print a line")
	}
}
