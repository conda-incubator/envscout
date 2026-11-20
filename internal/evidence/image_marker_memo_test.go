package evidence

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/anchore/stereoscope/pkg/file"
	"github.com/conda-incubator/envscout/internal/testimage"
)

func markerMemoFixture(t *testing.T, valid bool) (*imageCollector, *markerContractCatalog, file.Reference) {
	t.Helper()
	entry := packageMarker("cache/pkg/info/index.json", "python")
	if !valid {
		entry.Data = "{not json"
	}
	loaded := loadEvidenceImage(t, []testimage.Entry{entry})
	found, resolution, err := loaded.Image.SquashedTree().File("/cache/pkg/info/index.json")
	if err != nil || !found || resolution == nil || !resolution.HasReference() {
		t.Fatalf("marker reference: %v %v %v", found, resolution, err)
	}
	catalog := observeMarkerContract(loaded)
	return &imageCollector{ctx: context.Background(), loaded: loaded}, catalog, *resolution.Reference
}

func TestImageMarkerMemoValidAndInvalid(t *testing.T) {
	for _, valid := range []bool{false, true} {
		t.Run(map[bool]string{false: "invalid", true: "valid"}[valid], func(t *testing.T) {
			collector, catalog, ref := markerMemoFixture(t, valid)
			for i := 0; i < 2; i++ {
				got, err := collector.indexMarker(ref)
				if err != nil || got != valid {
					t.Fatalf("marker = %v, %v; want %v", got, err, valid)
				}
			}
			alias := ref
			alias.RealPath = "/another/caller/path"
			got, err := collector.indexMarker(alias)
			if err != nil || got != valid || catalog.opens[ref.ID()] != 1 || len(collector.markerValidity) != 1 {
				t.Fatalf("ID-keyed memo = %v, %v; opens=%v cache=%v", got, err, catalog.opens, collector.markerValidity)
			}
			fresh := imageCollector{ctx: context.Background(), loaded: collector.loaded}
			got, err = fresh.indexMarker(ref)
			if err != nil || got != valid || catalog.opens[ref.ID()] != 2 {
				t.Fatalf("new collection reused old memo: %v %v opens=%v", got, err, catalog.opens)
			}
		})
	}
}

func TestImageMarkerMemoReadErrorsRetry(t *testing.T) {
	for _, phase := range []string{"open", "read", "close"} {
		collector, catalog, ref := markerMemoFixture(t, true)
		hook := func(_ file.Reference, attempt int) error {
			if attempt == 1 {
				return errors.New("transient marker failure")
			}
			return nil
		}
		switch phase {
		case "open":
			catalog.openHook = hook
		case "read":
			catalog.readHook = hook
		case "close":
			catalog.closeHook = hook
		}
		if valid, err := collector.indexMarker(ref); valid || err == nil || len(collector.markerValidity) != 0 {
			t.Fatalf("read failure memoized: valid=%v err=%v cache=%v", valid, err, collector.markerValidity)
		}
		if valid, err := collector.indexMarker(ref); !valid || err != nil || catalog.opens[ref.ID()] != 2 {
			t.Fatalf("read failure was not retried: valid=%v err=%v opens=%v", valid, err, catalog.opens)
		}
	}
}

func TestImageMarkerMemoConsumersReadOnce(t *testing.T) {
	loaded := loadEvidenceImage(t, []testimage.Entry{
		packageMarker("cache/good/info/index.json", "pkg"),
		{Name: "cache/bad/info/index.json", Data: "{}"},
	})
	observer := observeMarkerContract(loaded)
	for pass := 1; pass <= 2; pass++ {
		target := collectFixture(t, loaded, CapFinalCache, CapLayerRetention)
		if len(target.Extracted) != 1 || len(target.Issues) != 4 || len(observer.opens) != 2 {
			t.Fatalf("validity reuse changed outcomes: %+v opens=%v", target, observer.opens)
		}
		for id, opens := range observer.opens {
			if opens != pass || observer.closed[id] != opens {
				t.Fatalf("reference %v opened %d times, want %d; closes=%d", id, opens, pass, observer.closed[id])
			}
		}
	}
}

func TestImageMarkerMemoCancellationBeforeHit(t *testing.T) {
	for _, valid := range []bool{false, true} {
		collector, catalog, ref := markerMemoFixture(t, valid)
		if _, err := collector.indexMarker(ref); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		collector.ctx = ctx
		if got, err := collector.indexMarker(ref); got || !errors.Is(err, context.Canceled) || catalog.opens[ref.ID()] != 1 {
			t.Fatalf("canceled hit = %v %v opens=%v", got, err, catalog.opens)
		}
	}
}

func TestImageMarkerMemoCapacityBypassesWithoutIssues(t *testing.T) {
	collector, catalog, ref := markerMemoFixture(t, true)
	collector.markerValidity = make(map[file.ID]bool)
	for i := 0; i < imageEntryLimit; i++ {
		collector.markerValidity[file.NewFileReference("/synthetic").ID()] = false
	}
	before := collector.target
	for i := 0; i < 2; i++ {
		if valid, err := collector.indexMarker(ref); !valid || err != nil {
			t.Fatalf("saturated bypass = %v %v", valid, err)
		}
	}
	if len(collector.markerValidity) != imageEntryLimit || catalog.opens[ref.ID()] != 2 || !reflect.DeepEqual(collector.target, before) {
		t.Fatalf("capacity changed target or retained entries: cache=%d opens=%v target=%+v", len(collector.markerValidity), catalog.opens, collector.target)
	}
	for id := range collector.markerValidity {
		delete(collector.markerValidity, id)
		break
	}
	collector.markerValidity[ref.ID()] = true
	if valid, err := collector.indexMarker(ref); !valid || err != nil || catalog.opens[ref.ID()] != 2 || len(collector.markerValidity) != imageEntryLimit {
		t.Fatalf("saturated existing hit = %v %v opens=%v", valid, err, catalog.opens)
	}
}
