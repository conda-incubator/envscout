package cli

import (
	"fmt"
	"io"
	"time"

	"github.com/anaconda/envscout/internal/discovery"
	"golang.org/x/term"
)

// statusLine owns all transient terminal writes; scanner workers only update counters.
type statusLine struct {
	writer io.Writer
	width  int
	stop   chan struct{}
	done   chan struct{}
}

func startStatus(writer io.Writer, snapshot func() string) *statusLine {
	if !isTerminal(writer) {
		return nil
	}
	s := &statusLine{writer: writer, stop: make(chan struct{}), done: make(chan struct{})}
	if file, ok := writer.(interface{ Fd() uintptr }); ok {
		s.width, _, _ = term.GetSize(int(file.Fd()))
	}
	s.draw(snapshot())
	go func() {
		defer close(s.done)
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				s.draw(snapshot())
			case <-s.stop:
				return
			}
		}
	}()
	return s
}

func (s *statusLine) draw(text string) {
	// Truncate the status to the available columns so it cannot wrap into the report.
	if s.width > 0 && len(text) >= s.width {
		text = text[:s.width-1]
	}
	_, _ = fmt.Fprintf(s.writer, "\r\x1b[2K%s", text)
}

func (s *statusLine) close() {
	if s == nil {
		return
	}
	close(s.stop)
	<-s.done
	_, _ = fmt.Fprint(s.writer, "\r\x1b[2K")
}

func findCondaWithStatus(roots []string, writer io.Writer) (discovery.Report, error) {
	progress := new(discovery.Progress)
	status := startStatus(writer, func() string {
		return fmt.Sprintf("Folders: %d  Envs: %d", progress.Folders.Load(), progress.Environments.Load())
	})
	defer status.close()
	return discovery.FindCondaWithProgress(roots, progress)
}
