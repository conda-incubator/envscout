package evidence

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/filetree"
	"github.com/conda-incubator/envscout/internal/testimage"
)

type resolutionMemoReader struct {
	filetree.Reader
	calls  int
	paths  map[file.Path]int
	lookup func(file.Path) (bool, *file.Resolution, error)
}

func (r *resolutionMemoReader) File(p file.Path, options ...filetree.LinkResolutionOption) (bool, *file.Resolution, error) {
	r.calls++
	if r.paths != nil {
		r.paths[p]++
	}
	if r.lookup != nil {
		return r.lookup(p)
	}
	return r.Reader.File(p, options...)
}

func TestImageResolutionMemoConsumers(t *testing.T) {
	loaded := loadEvidenceImage(t, []testimage.Entry{
		packageMarker("cache/pkg/info/index.json", "pkg"),
		{Name: "cache/pkg/data", Data: "payload"},
		{Name: "cache/pkg/alias", Type: tar.TypeSymlink, Link: "data"},
		{Name: "app/alias", Type: tar.TypeSymlink, Link: "/cache/pkg/data"},
	})
	reader := &resolutionMemoReader{Reader: loaded.Image.SquashedTree(), paths: map[file.Path]int{}}
	c := imageCollector{ctx: context.Background(), loaded: loaded, tree: reader, caches: map[string]bool{"/cache": true},
		target: markerContractTarget(loaded, NotCollected, Complete, Complete), limited: map[string]bool{}}
	if err := c.collectCacheLinks(); err != nil {
		t.Fatal(err)
	}
	if err := c.collectLayers(); err != nil {
		t.Fatal(err)
	}
	if !c.target.CacheLinked || len(c.target.Issues) != 0 || len(c.target.Retained) != 0 || c.target.Coverage[CapCacheLinkDependencies] != Complete || c.target.Coverage[CapLayerRetention] != Complete {
		t.Fatalf("consumer outcomes: %+v", c.target)
	}
	for _, p := range []file.Path{"/cache/pkg/alias", "/app/alias"} {
		if reader.paths[p] != 1 {
			t.Fatalf("%s lookup calls=%d, want=1", p, reader.paths[p])
		}
	}
}

func TestImageResolutionMemoHitCheckpoints(t *testing.T) {
	for _, ref := range []*file.Reference{nil, file.NewFileReference("/target")} {
		for _, tc := range []struct {
			name    string
			states  []error
			checks  int
			message string
		}{
			{"success", nil, 2, ""},
			{"pre-cancel", []error{context.Canceled}, 1, "context canceled"},
			{"post-slot-cancel", []error{nil, context.Canceled}, 3, "context canceled"},
			{"third-check-error", []error{nil, context.Canceled, context.DeadlineExceeded}, 3, "context deadline exceeded"},
		} {
			t.Run(fmt.Sprintf("%s/nil=%v", tc.name, ref == nil), func(t *testing.T) {
				ctx := &imageResolutionContractContext{Context: context.Background(), t: t, states: tc.states, budget: tc.checks}
				c := imageCollector{ctx: ctx, resolvedReferences: map[string]*file.Reference{"/alias": ref}}
				got, err := c.resolveReference("/alias")
				want := ref
				if tc.message != "" {
					want = nil
				}
				assertImageResolutionContract(t, got, want, err, tc.message)
				if ctx.calls != tc.checks {
					t.Fatalf("context calls=%d, want=%d", ctx.calls, tc.checks)
				}
			})
		}
	}
}

func TestImageResolutionMemoReuse(t *testing.T) {
	tree := filetree.New()
	ref, err := tree.AddFile("/cache/pkg/data")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tree.AddSymLink("/alias", "/cache/pkg/data"); err != nil {
		t.Fatal(err)
	}
	if _, err := tree.AddSymLink("/directory", "/cache/pkg"); err != nil {
		t.Fatal(err)
	}
	reader := &resolutionMemoReader{Reader: tree}
	c := imageCollector{ctx: context.Background(), tree: reader}
	for _, p := range []string{"/alias", "/directory", "/directory/data"} {
		for i := 0; i < 2; i++ {
			resolved, err := c.resolveReference(p)
			if err != nil || (resolved == nil) != (p == "/directory") || resolved != nil && resolved.ID() != ref.ID() {
				t.Fatalf("%s: %v, %v", p, resolved, err)
			}
		}
	}
	if reader.calls != 3 || len(c.resolvedReferences) != 3 {
		t.Fatalf("calls=%d, entries=%d", reader.calls, len(c.resolvedReferences))
	}
	wantBytes := len("/alias") + len("/directory") + len("/directory/data") + 2*len(ref.RealPath)
	if c.resolvedReferenceBytes != wantBytes {
		t.Fatalf("owned path bytes=%d, want=%d", c.resolvedReferenceBytes, wantBytes)
	}
	for i := 0; i < 2; i++ {
		if _, err := c.resolveReference("/cache/pkg/data"); err != nil {
			t.Fatal(err)
		}
	}
	if reader.calls != 5 || len(c.resolvedReferences) != 3 {
		t.Fatalf("direct lookup cached: calls=%d, entries=%d", reader.calls, len(c.resolvedReferences))
	}
	fresh := imageCollector{ctx: context.Background(), tree: reader}
	if _, err := fresh.resolveReference("/alias"); err != nil || reader.calls != 6 {
		t.Fatalf("fresh collection: calls=%d, err=%v", reader.calls, err)
	}
	resolved, err := c.resolveReference("/alias")
	if err != nil {
		t.Fatal(err)
	}
	resolved.RealPath = "/caller-change"
	resolved, err = c.resolveReference("/alias")
	if err != nil || resolved.RealPath != ref.RealPath || resolved.ID() != ref.ID() {
		t.Fatalf("caller changed cached scalar: %v, %v", resolved, err)
	}
}

func TestImageResolutionMemoExactKeys(t *testing.T) {
	ref := file.NewFileReference("/target")
	reader := &resolutionMemoReader{lookup: func(p file.Path) (bool, *file.Resolution, error) {
		return true, file.NewResolution(p, ref, []file.Resolution{{RequestPath: p}}), nil
	}}
	c := imageCollector{ctx: context.Background(), tree: reader}
	for _, p := range []string{"/alias", "alias", "/./alias"} {
		for i := 0; i < 2; i++ {
			if got, err := c.resolveReference(p); err != nil || got.ID() != ref.ID() {
				t.Fatalf("%q: %v, %v", p, got, err)
			}
		}
	}
	if reader.calls != 3 || len(c.resolvedReferences) != 3 {
		t.Fatalf("keys normalized: calls=%d, entries=%d", reader.calls, len(c.resolvedReferences))
	}
	if c.resolvedReferenceBytes != len("/alias")+len("alias")+len("/./alias")+3*len(ref.RealPath) {
		t.Fatalf("owned path bytes=%d", c.resolvedReferenceBytes)
	}
}

func TestImageResolutionMemoFailuresAndCancellation(t *testing.T) {
	ref := file.NewFileReference("/target")
	for _, failure := range []string{"lookup-error", "not-found", "nil-resolution", "post-lookup-cancel"} {
		t.Run(failure, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			reader := &resolutionMemoReader{}
			reader.lookup = func(p file.Path) (bool, *file.Resolution, error) {
				if reader.calls == 1 {
					switch failure {
					case "lookup-error":
						return false, nil, errors.New("lookup failed")
					case "not-found":
						return false, nil, nil
					case "nil-resolution":
						return true, nil, nil
					case "post-lookup-cancel":
						cancel()
					}
				}
				return true, file.NewResolution(p, ref, []file.Resolution{{RequestPath: p}}), nil
			}
			c := imageCollector{ctx: ctx, tree: reader}
			if _, err := c.resolveReference("/alias"); err == nil || len(c.resolvedReferences) != 0 || c.resolvedReferenceBytes != 0 {
				t.Fatalf("failure cached: err=%v, entries=%d, bytes=%d", err, len(c.resolvedReferences), c.resolvedReferenceBytes)
			}
			c.ctx = context.Background()
			for i := 0; i < 2; i++ {
				got, err := c.resolveReference("/alias")
				if err != nil || got == nil || got.ID() != ref.ID() {
					t.Fatalf("retry: %v, %v", got, err)
				}
			}
			if reader.calls != 2 || len(c.resolvedReferences) != 1 {
				t.Fatalf("calls=%d, entries=%d", reader.calls, len(c.resolvedReferences))
			}
			c.ctx = ctx
			cancel()
			if _, err := c.resolveReference("/alias"); !errors.Is(err, context.Canceled) || reader.calls != 2 {
				t.Fatalf("pre-canceled hit: err=%v, calls=%d", err, reader.calls)
			}
		})
	}
}

func TestImageResolutionMemoBounds(t *testing.T) {
	ref := file.NewFileReference("/target")
	reader := &resolutionMemoReader{lookup: func(p file.Path) (bool, *file.Resolution, error) {
		return true, file.NewResolution(p, ref, []file.Resolution{{RequestPath: p}}), nil
	}}
	t.Run("entry-cap", func(t *testing.T) {
		c := imageCollector{ctx: context.Background(), tree: reader, resolvedReferences: map[string]*file.Reference{}}
		for i := 0; i < imageEntryLimit; i++ {
			c.resolvedReferences[fmt.Sprintf("/old-%d", i)] = nil
		}
		before := reader.calls
		for i := 0; i < 2; i++ {
			if got, err := c.resolveReference("/new"); err != nil || got.ID() != ref.ID() {
				t.Fatalf("bypassed lookup: %v, %v", got, err)
			}
		}
		if got, err := c.resolveReference("/old-0"); err != nil || got != nil || reader.calls != before+2 || len(c.resolvedReferences) != imageEntryLimit {
			t.Fatalf("existing nil hit: %v, %v, calls=%d, entries=%d", got, err, reader.calls, len(c.resolvedReferences))
		}
	})
	t.Run("byte-cap", func(t *testing.T) {
		c := imageCollector{ctx: context.Background(), tree: reader, resolvedReferenceBytes: imageResolutionBytesLimit - len("/last") - len(ref.RealPath)}
		before := reader.calls
		if _, err := c.resolveReference("/last"); err != nil || c.resolvedReferenceBytes != imageResolutionBytesLimit || len(c.resolvedReferences) != 1 {
			t.Fatalf("exact byte bound: %v, bytes=%d, entries=%d", err, c.resolvedReferenceBytes, len(c.resolvedReferences))
		}
		for i := 0; i < 2; i++ {
			if _, err := c.resolveReference("/bypass"); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := c.resolveReference("/last"); err != nil || reader.calls != before+3 || c.resolvedReferenceBytes != imageResolutionBytesLimit {
			t.Fatalf("saturated byte cache: %v, calls=%d, bytes=%d", err, reader.calls, c.resolvedReferenceBytes)
		}
	})
	t.Run("oversized-key", func(t *testing.T) {
		c := imageCollector{ctx: context.Background(), tree: reader}
		if _, err := c.resolveReference(strings.Repeat("k", imageResolutionBytesLimit+1)); err != nil || len(c.resolvedReferences) != 0 || c.resolvedReferenceBytes != 0 {
			t.Fatalf("oversized key retained: %v, entries=%d, bytes=%d", err, len(c.resolvedReferences), c.resolvedReferenceBytes)
		}
	})
	t.Run("oversized-reference", func(t *testing.T) {
		large := file.NewFileReference(file.Path(strings.Repeat("r", imageResolutionBytesLimit)))
		reader := &resolutionMemoReader{lookup: func(p file.Path) (bool, *file.Resolution, error) {
			return true, file.NewResolution(p, large, nil), nil
		}}
		c := imageCollector{ctx: context.Background(), tree: reader}
		if got, err := c.resolveReference("/alias"); err != nil || got.ID() != large.ID() || len(c.resolvedReferences) != 0 || c.resolvedReferenceBytes != 0 {
			t.Fatalf("oversized reference retained: %v, entries=%d, bytes=%d", err, len(c.resolvedReferences), c.resolvedReferenceBytes)
		}
	})
}
