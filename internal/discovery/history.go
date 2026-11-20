package discovery

import (
	"bufio"
	"io"
	"strings"
)

// parseHistoryRevision counts transaction headers, including headers with no
// package changes. Readers own cancellation and the total byte bound.
func parseHistoryRevision(r io.Reader) (*int, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 4096), maxMetadataBytes)
	count := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "==>") {
			continue
		}
		rest := strings.TrimSpace(strings.TrimPrefix(line, "==>"))
		end := strings.Index(rest, "<==")
		if end > 0 && strings.TrimSpace(rest[:end]) != "" {
			count++
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if count == 0 {
		return nil, nil
	}
	latest := count - 1
	return &latest, nil
}
