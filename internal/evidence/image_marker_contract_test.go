package evidence

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"io"
	"reflect"
	"sync"
	"testing"

	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/conda-incubator/envscout/internal/imageinput"
	"github.com/conda-incubator/envscout/internal/testimage"
)

type markerContractCatalog struct {
	image.FileCatalogReader
	mu        sync.Mutex
	opens     map[file.ID]int
	readers   map[file.ID]int
	closed    map[file.ID]int
	paths     map[file.ID]string
	openHook  func(file.Reference, int) error
	readHook  func(file.Reference, int) error
	closeHook func(file.Reference, int) error
}

func observeMarkerContract(loaded *imageinput.Loaded) *markerContractCatalog {
	catalog := &markerContractCatalog{
		FileCatalogReader: loaded.Image.FileCatalog,
		opens:             map[file.ID]int{},
		readers:           map[file.ID]int{},
		closed:            map[file.ID]int{},
		paths:             map[file.ID]string{},
	}
	loaded.Image.FileCatalog = catalog
	return catalog
}

func (catalog *markerContractCatalog) Open(ref file.Reference) (io.ReadCloser, error) {
	catalog.mu.Lock()
	catalog.opens[ref.ID()]++
	attempt := catalog.opens[ref.ID()]
	catalog.paths[ref.ID()] = string(ref.RealPath)
	catalog.mu.Unlock()
	if catalog.openHook != nil {
		if err := catalog.openHook(ref, attempt); err != nil {
			return nil, err
		}
	}
	reader, err := catalog.FileCatalogReader.Open(ref)
	if err != nil {
		return nil, err
	}
	catalog.mu.Lock()
	catalog.readers[ref.ID()]++
	catalog.mu.Unlock()
	return &markerContractReader{ReadCloser: reader, catalog: catalog, ref: ref, attempt: attempt}, nil
}

type markerContractReader struct {
	io.ReadCloser
	catalog *markerContractCatalog
	ref     file.Reference
	attempt int
}

func (reader *markerContractReader) Read(p []byte) (int, error) {
	if reader.catalog.readHook != nil {
		if err := reader.catalog.readHook(reader.ref, reader.attempt); err != nil {
			return 0, err
		}
	}
	return reader.ReadCloser.Read(p)
}

func (reader *markerContractReader) Close() error {
	err := reader.ReadCloser.Close()
	reader.catalog.mu.Lock()
	reader.catalog.closed[reader.ref.ID()]++
	reader.catalog.mu.Unlock()
	if reader.catalog.closeHook != nil {
		return errors.Join(err, reader.catalog.closeHook(reader.ref, reader.attempt))
	}
	return err
}

func (catalog *markerContractCatalog) markerReads(t *testing.T, p string) map[file.ID]int {
	t.Helper()
	catalog.mu.Lock()
	defer catalog.mu.Unlock()
	reads := map[file.ID]int{}
	for id, name := range catalog.paths {
		if name == p {
			reads[id] = catalog.opens[id]
			if catalog.closed[id] != catalog.readers[id] {
				t.Fatalf("%s ref %v: readers=%d closes=%d", p, id, catalog.readers[id], catalog.closed[id])
			}
		}
	}
	if len(reads) == 0 {
		t.Fatalf("marker observer saw no opens for %s", p)
	}
	// HEAD c5dcd8d opens a surviving regular marker three times with final-cache
	// and layer-retention. Counts are observations, not a redundant-I/O contract.
	t.Logf("marker %s opens by reference: %v", p, reads)
	return reads
}

func markerContractTarget(loaded *imageinput.Loaded, cache, links, layers string) Target {
	identity := loaded.Identity
	return Target{
		ID: "oci:" + identity.ManifestDigest + "@linux/amd64", Kind: "oci-archive", Input: identity.Input, Image: &identity,
		Roots: []string{}, Prefixes: []Prefix{}, Archives: []Artifact{}, Extracted: []Artifact{},
		Tools: []Artifact{}, Shells: []Artifact{}, Retained: []Artifact{}, Issues: []Issue{},
		Coverage: map[string]string{
			"prefixes": NotCollected, "conda-records": NotCollected, "history": NotCollected, "tooling-prefix": NotCollected,
			"final-cache": cache, "cache-link-dependencies": links, "layer-retention": layers,
			"runtime-config": NotCollected, "os-package-tools": NotCollected, "shell-tools": NotCollected,
		},
	}
}

func markerContractReference(loaded *imageinput.Loaded, layer int, p string) string {
	return fmt.Sprintf("%d:%s:%s", layer, loaded.Image.Metadata.Config.RootFS.DiffIDs[layer], p)
}

func assertMarkerContract(t *testing.T, got, want Target) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("marker target = %+v\nwant %+v", got, want)
	}
}

func TestImageMarkerContractConsumers(t *testing.T) {
	for _, invalid := range []bool{false, true} {
		t.Run(fmt.Sprint(invalid), func(t *testing.T) {
			entries := []testimage.Entry{
				packageMarker("cache/good/info/index.json", "pkg"),
				{Name: "cache/good/data", Data: "payload"},
				{Name: "cache/pkg-1.0-0.conda", Data: "archive"},
			}
			if invalid {
				entries = append(entries, testimage.Entry{Name: "cache/bad/info/index.json", Data: "{}"})
			}
			loaded := loadEvidenceImage(t, entries)
			for _, selection := range []struct {
				name                 string
				caps                 []string
				cache, links, layers string
			}{
				{"cache", []string{"final-cache"}, Complete, NotCollected, NotCollected},
				{"layers", []string{"layer-retention"}, NotCollected, NotCollected, Complete},
				{"all", []string{"final-cache", "cache-link-dependencies", "layer-retention"}, Complete, Complete, Complete},
			} {
				t.Run(selection.name, func(t *testing.T) {
					observer := observeMarkerContract(loaded)
					defer func() { loaded.Image.FileCatalog = observer.FileCatalogReader }()
					want := markerContractTarget(loaded, selection.cache, selection.links, selection.layers)
					if selection.cache != NotCollected {
						want.Archives = []Artifact{{Path: "/cache/pkg-1.0-0.conda", Kind: "archive", Bytes: 7, Reference: markerContractReference(loaded, 0, "/cache/pkg-1.0-0.conda")}}
						want.Extracted = []Artifact{{Path: "/cache/good", Kind: "extracted", Bytes: 86, Reference: markerContractReference(loaded, 0, "/cache/good/info/index.json")}}
					}
					if invalid {
						if selection.links != NotCollected {
							want.Coverage["cache-link-dependencies"] = Partial
							want.Issues = append(want.Issues, Issue{Capability: "cache-link-dependencies", Path: "/cache/bad/info/index.json", Message: "invalid conda package marker"})
						}
						if selection.cache != NotCollected {
							want.Coverage["final-cache"] = Partial
							want.Issues = append(want.Issues,
								Issue{Capability: "final-cache", Path: "/cache/bad/info/index.json", Message: "invalid conda package marker"},
								Issue{Capability: "final-cache", Path: "/cache/bad/info/index.json", Message: "invalid extracted cache marker"})
						}
						if selection.layers != NotCollected {
							want.Coverage["layer-retention"] = Partial
							want.Issues = append(want.Issues,
								Issue{Capability: "layer-retention", Path: "/cache/bad/info/index.json", Message: "invalid conda package marker"},
								Issue{Capability: "layer-retention", Path: "/cache/bad/info/index.json", Message: "invalid historical conda marker"})
						}
					}
					// Reusing the loaded image must not reuse a previous collector's memo.
					for pass := 0; pass < 2; pass++ {
						before := observer.opensTotal()
						assertMarkerContract(t, collectFixture(t, loaded, selection.caps...), want)
						if observer.opensTotal() <= before {
							t.Fatal("new collection did not open any marker references")
						}
					}
					observer.markerReads(t, "/cache/good/info/index.json")
					if invalid {
						observer.markerReads(t, "/cache/bad/info/index.json")
					}
				})
			}
		})
	}
}

func (catalog *markerContractCatalog) opensTotal() int {
	catalog.mu.Lock()
	defer catalog.mu.Unlock()
	total := 0
	for _, count := range catalog.opens {
		total += count
	}
	return total
}

func TestImageMarkerContractNonregular(t *testing.T) {
	for _, kind := range []byte{tar.TypeDir, tar.TypeFifo, tar.TypeSymlink} {
		t.Run(fmt.Sprint(kind), func(t *testing.T) {
			loaded := loadEvidenceImage(t, []testimage.Entry{
				packageMarker("cache/good/info/index.json", "pkg"),
				{Name: "cache/bad/info/index.json", Type: kind, Link: "/cache/good/info/index.json"},
			})
			observer := observeMarkerContract(loaded)
			want := markerContractTarget(loaded, Partial, Partial, Partial)
			want.Extracted = []Artifact{{Path: "/cache/good", Kind: "extracted", Bytes: 79, Reference: markerContractReference(loaded, 0, "/cache/good/info/index.json")}}
			message := "evidence is not a regular file"
			if kind == tar.TypeSymlink {
				message = "conda marker is not a regular file"
			}
			want.Issues = []Issue{
				{Capability: "cache-link-dependencies", Path: "/cache/bad/info/index.json", Message: message},
				{Capability: "final-cache", Path: "/cache/bad/info/index.json", Message: message},
				{Capability: "final-cache", Path: "/cache/bad/info/index.json", Message: "extracted cache marker is not a regular file"},
				{Capability: "layer-retention", Path: "/cache/bad/info/index.json", Message: message},
			}
			// Stereoscope represents a FIFO as a regular tree node, but its catalog
			// metadata rejects bounded reads in all three consumers.
			if kind == tar.TypeFifo {
				want.Issues[2].Message = "evidence is not a regular file"
				want.Issues = append(want.Issues, Issue{Capability: "layer-retention", Path: "/cache/bad/info/index.json", Message: "evidence is not a regular file"})
			}
			assertMarkerContract(t, collectFixture(t, loaded, "final-cache", "cache-link-dependencies", "layer-retention"), want)
			observer.markerReads(t, "/cache/good/info/index.json")
			for _, p := range observer.paths {
				if p == "/cache/bad/info/index.json" {
					t.Fatal("nonregular marker was opened")
				}
			}
		})
	}
}

func TestImageMarkerContractAdoptedHardlink(t *testing.T) {
	loaded := loadEvidenceImage(t, []testimage.Entry{
		packageMarker("raw-index", "pkg"),
		{Name: "cache/pkg/info/index.json", Type: tar.TypeLink, Link: "raw-index"},
	}, []testimage.Entry{{Name: "raw-index", Data: "{}"}})
	observer := observeMarkerContract(loaded)
	want := markerContractTarget(loaded, Complete, Partial, Partial)
	want.Extracted = []Artifact{{Path: "/cache/pkg", Kind: "extracted", Bytes: 79, Reference: markerContractReference(loaded, 0, "/cache/pkg/info/index.json")}}
	want.Issues = []Issue{
		{Capability: "cache-link-dependencies", Path: "/cache/pkg/info/index.json", Message: "original hardlink content identity is unavailable"},
		{Capability: "layer-retention", Path: "/cache/pkg/info/index.json", Message: "original hardlink content identity is unavailable"},
		{Capability: "layer-retention", Path: "/cache/pkg/info/index.json", Message: "original hardlink content identity is unavailable"},
	}
	assertMarkerContract(t, collectFixture(t, loaded, "final-cache", "cache-link-dependencies", "layer-retention"), want)
	observer.markerReads(t, "/cache/pkg/info/index.json")
}

func TestImageMarkerContractReplacement(t *testing.T) {
	loaded := loadEvidenceImage(t, []testimage.Entry{
		packageMarker("cache/pkg/info/index.json", "pkg"),
		{Name: "cache/pkg/data", Data: "old"},
	}, []testimage.Entry{{Name: "cache/pkg/info/index.json", Data: "{}"}})
	observer := observeMarkerContract(loaded)
	want := markerContractTarget(loaded, Partial, NotCollected, Partial)
	blob := manifestOf(t, loaded).Layers[0]
	want.Retained = []Artifact{{Path: "/cache/pkg", Kind: "extracted-overwritten", Bytes: 79, Layer: 0,
		DiffID: loaded.Image.Metadata.Config.RootFS.DiffIDs[0].String(), BlobDigest: blob.Digest.String(), LayerBytes: blob.Size,
		Reference: markerContractReference(loaded, 0, "/cache/pkg/info/index.json")}}
	want.Issues = []Issue{
		{Capability: "final-cache", Path: "/cache/pkg/info/index.json", Message: "invalid conda package marker"},
		{Capability: "layer-retention", Path: "/cache/pkg/info/index.json", Message: "invalid conda package marker"},
		{Capability: "layer-retention", Path: "/cache/pkg/info/index.json", Message: "invalid historical conda marker"},
	}
	assertMarkerContract(t, collectFixture(t, loaded, "final-cache", "layer-retention"), want)
	if reads := observer.markerReads(t, "/cache/pkg/info/index.json"); len(reads) != 2 {
		t.Fatalf("same path across layers has %d observed reference IDs, want 2", len(reads))
	}
}

func TestImageMarkerContractWhiteoutAndLaterPositive(t *testing.T) {
	loaded := loadEvidenceImage(t, []testimage.Entry{
		packageMarker("cache/old/info/index.json", "pkg"),
		{Name: "cache/old/data", Data: "old"},
		{Name: "cache/pkg-1.0-0.conda", Data: "archive"},
	}, []testimage.Entry{
		{Name: "cache/.wh.old"},
		{Name: "cache/.wh.pkg-1.0-0.conda"},
		packageMarker("cache/new/info/index.json", "pkg"),
		{Name: "cache/new/data", Data: "new"},
	})
	observer := observeMarkerContract(loaded)
	want := markerContractTarget(loaded, Complete, NotCollected, Complete)
	want.Extracted = []Artifact{{Path: "/cache/new", Kind: "extracted", Bytes: 82, Reference: markerContractReference(loaded, 1, "/cache/new/info/index.json")}}
	blob := manifestOf(t, loaded).Layers[0]
	want.Retained = []Artifact{
		{Path: "/cache/old", Kind: "extracted-hidden", Bytes: 82, Layer: 0,
			DiffID: loaded.Image.Metadata.Config.RootFS.DiffIDs[0].String(), BlobDigest: blob.Digest.String(), LayerBytes: blob.Size,
			Reference: markerContractReference(loaded, 0, "/cache/old/data")},
		{Path: "/cache/pkg-1.0-0.conda", Kind: "archive-hidden", Bytes: 7, Layer: 0,
			DiffID: loaded.Image.Metadata.Config.RootFS.DiffIDs[0].String(), BlobDigest: blob.Digest.String(), LayerBytes: blob.Size,
			Reference: markerContractReference(loaded, 0, "/cache/pkg-1.0-0.conda")},
	}
	assertMarkerContract(t, collectFixture(t, loaded, "final-cache", "layer-retention"), want)
	observer.markerReads(t, "/cache/old/info/index.json")
	observer.markerReads(t, "/cache/new/info/index.json")
}

func TestImageMarkerContractReadFailuresRetry(t *testing.T) {
	for _, phase := range []string{"open", "read", "close"} {
		t.Run(phase, func(t *testing.T) {
			loaded := loadEvidenceImage(t, []testimage.Entry{
				packageMarker("cache/good/info/index.json", "pkg"),
				packageMarker("cache/retry/info/index.json", "pkg"),
			})
			observer := observeMarkerContract(loaded)
			failure := errors.New("private injected read failure")
			hook := func(ref file.Reference, attempt int) error {
				if string(ref.RealPath) == "/cache/retry/info/index.json" && attempt == 1 {
					return failure
				}
				return nil
			}
			message := "file content could not be read"
			switch phase {
			case "open":
				observer.openHook = hook
				message = "file content is unavailable"
			case "read":
				observer.readHook = hook
			case "close":
				observer.closeHook = hook
			}
			want := markerContractTarget(loaded, Partial, Partial, Partial)
			want.Extracted = []Artifact{
				{Path: "/cache/good", Kind: "extracted", Bytes: 79, Reference: markerContractReference(loaded, 0, "/cache/good/info/index.json")},
				{Path: "/cache/retry", Kind: "extracted", Bytes: 79, Reference: markerContractReference(loaded, 0, "/cache/retry/info/index.json")},
			}
			want.Issues = []Issue{
				{Capability: "cache-link-dependencies", Path: "/cache/retry/info/index.json", Message: message},
				{Capability: "final-cache", Path: "/cache/retry/info/index.json", Message: message},
				{Capability: "layer-retention", Path: "/cache/retry/info/index.json", Message: message},
			}
			assertMarkerContract(t, collectFixture(t, loaded, "final-cache", "cache-link-dependencies", "layer-retention"), want)
			reads := observer.markerReads(t, "/cache/retry/info/index.json")
			if len(reads) != 1 {
				t.Fatalf("retry changed reference identity: %v", reads)
			}
			for _, count := range reads {
				if count < 2 {
					t.Fatal("read failure was not retried by a later consumer")
				}
			}
		})
	}
}

func TestImageMarkerContractCancellationKeepsPositives(t *testing.T) {
	loaded := loadEvidenceImage(t, []testimage.Entry{packageMarker("cache/old/info/index.json", "pkg")}, []testimage.Entry{
		{Name: "cache/.wh.old"},
		packageMarker("cache/new/info/index.json", "pkg"),
		{Name: "cache/new/data", Data: "payload"},
		{Name: "cache/pkg-1.0-0.conda", Data: "archive"},
	})
	observer := observeMarkerContract(loaded)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	observer.readHook = func(ref file.Reference, _ int) error {
		if string(ref.RealPath) == "/cache/old/info/index.json" {
			cancel()
			return context.Canceled
		}
		return nil
	}
	got, err := CollectImage(ctx, loaded, Request{Capabilities: []string{"final-cache", "cache-link-dependencies", "layer-retention"}})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation identity = %v", err)
	}
	want := markerContractTarget(loaded, Partial, Partial, Partial)
	want.Archives = []Artifact{{Path: "/cache/pkg-1.0-0.conda", Kind: "archive", Bytes: 7, Reference: markerContractReference(loaded, 1, "/cache/pkg-1.0-0.conda")}}
	want.Extracted = []Artifact{{Path: "/cache/new", Kind: "extracted", Bytes: 86, Reference: markerContractReference(loaded, 1, "/cache/new/info/index.json")}}
	assertMarkerContract(t, got, want)
	observer.markerReads(t, "/cache/old/info/index.json")
	observer.markerReads(t, "/cache/new/info/index.json")
}
