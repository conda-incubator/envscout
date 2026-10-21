.PHONY: build build-pixi native-pixi build-linux build-darwin build-windows image-archive example-image example-lint lint-demo test test-pixi test-race vet lint fmt fmt-check mod-tidy actionlint

IMAGE ?=
PLATFORM ?= linux/amd64
ARCHIVE ?= bin/image.tar
SKOPEO ?= skopeo
EXAMPLE_ARCHIVE ?= bin/lint-example.tar
BUILDER ?=

PIXI_MODULE = github.com/conda-incubator/go-rattler
PIXI_TARGET_DIR = $(abspath .go-rattler-native)
PIXI_NATIVE_LIB_DIR = $(PIXI_TARGET_DIR)/$(if $(CARGO_BUILD_TARGET),$(CARGO_BUILD_TARGET)/)release

build:
	go build -o envscout ./cmd/envscout

build-pixi: native-pixi
	CGO_ENABLED=1 CGO_LDFLAGS="-L$(PIXI_NATIVE_LIB_DIR) $(CGO_LDFLAGS)" go build -tags pixi -modfile=go.pixi.mod -o envscout ./cmd/envscout

native-pixi:
	go mod download -modfile=go.pixi.mod $(PIXI_MODULE)
	@source_dir="$$(go list -modfile=go.pixi.mod -m -f '{{.Dir}}' $(PIXI_MODULE))"; \
	  CARGO_TARGET_DIR="$(PIXI_TARGET_DIR)" cargo build --manifest-path "$$source_dir/internal/native/Cargo.toml" --release --locked

build-linux:
	mkdir -p bin
	GOOS=linux GOARCH=amd64 go build -o bin/envscout-linux-amd64 ./cmd/envscout

build-darwin:
	mkdir -p bin
	GOOS=darwin GOARCH=arm64 go build -o bin/envscout-darwin-arm64 ./cmd/envscout

build-windows:
	mkdir -p bin
	GOOS=windows GOARCH=amd64 go build -o bin/envscout-windows-amd64.exe ./cmd/envscout

# Pass user values through the environment, not as shell source.
image-archive: export IMAGE := $(IMAGE)
image-archive: export PLATFORM := $(PLATFORM)
image-archive: export ARCHIVE := $(ARCHIVE)
image-archive: export SKOPEO := $(SKOPEO)
image-archive:
	@set -eu; \
	  test -n "$$IMAGE" || { printf '%s\n' 'Usage: make image-archive IMAGE=registry/repository:tag [PLATFORM=linux/amd64] [ARCHIVE=bin/image.tar]' >&2; exit 1; }; \
	  case "$$PLATFORM" in ''|/*|*/|*//*) printf '%s\n' 'PLATFORM must be OS/ARCH[/VARIANT]' >&2; exit 1;; esac; \
	  IFS=/; set -f; set -- $$PLATFORM; unset IFS; \
	  test "$$#" -eq 2 || test "$$#" -eq 3 || { printf '%s\n' 'PLATFORM must be OS/ARCH[/VARIANT]' >&2; exit 1; }; \
	  for part in "$$@"; do case "$$part" in *[!a-zA-Z0-9_-]*) printf '%s\n' 'Invalid PLATFORM component' >&2; exit 1;; esac; done; \
	  os="$$1"; arch="$$2"; variant="$${3-}"; \
	  set -- --override-os "$$os" --override-arch "$$arch"; \
	  if test -n "$$variant"; then set -- "$$@" --override-variant "$$variant"; fi; \
	  test ! -e "$$ARCHIVE" && test ! -L "$$ARCHIVE" || { printf 'Archive already exists: %s\n' "$$ARCHIVE" >&2; exit 1; }; \
	  mkdir -p "$$(dirname "$$ARCHIVE")"; \
	  "$$SKOPEO" "$$@" copy --format oci --dest-compress-format gzip --dest-force-compress-format "docker://$$IMAGE" "oci-archive:$$ARCHIVE"

test:
	go test ./...

lint-demo:
	go test -count=1 -v ./internal/cli -run '^TestLintImageMultipleRulesAndLayerRetention$$'

example-image: export EXAMPLE_ARCHIVE := $(EXAMPLE_ARCHIVE)
example-image: export PLATFORM := $(PLATFORM)
example-image: export BUILDER := $(BUILDER)
example-image:
	@set -eu; \
	  test ! -e "$$EXAMPLE_ARCHIVE" && test ! -L "$$EXAMPLE_ARCHIVE" || { printf 'Archive already exists: %s\n' "$$EXAMPLE_ARCHIVE" >&2; exit 1; }; \
	  case "$$EXAMPLE_ARCHIVE" in *','*|*'='*) printf '%s\n' 'EXAMPLE_ARCHIVE must not contain comma or equals' >&2; exit 1;; esac; \
	  mkdir -p "$$(dirname "$$EXAMPLE_ARCHIVE")"; \
	  builder="$$BUILDER"; temporary=''; staging="$$EXAMPLE_ARCHIVE.partial-$$$$"; \
	  trap 'rm -f "$$staging"; if test -n "$$temporary"; then docker buildx rm "$$temporary" >/dev/null 2>&1 || true; fi' EXIT; \
	  if test -z "$$builder"; then \
	    builder="envscout-example-$$$$"; \
	    docker buildx create --name "$$builder" --driver docker-container >/dev/null; \
	    temporary="$$builder"; \
	  fi; \
	  docker buildx build --builder "$$builder" --platform "$$PLATFORM" --provenance=false \
	    --output "type=oci,dest=$$staging,compression=gzip,force-compression=true" examples; \
	  test ! -e "$$EXAMPLE_ARCHIVE" && test ! -L "$$EXAMPLE_ARCHIVE" || { printf 'Archive appeared during build: %s\n' "$$EXAMPLE_ARCHIVE" >&2; exit 1; }; \
	  mv "$$staging" "$$EXAMPLE_ARCHIVE"

example-lint: export EXAMPLE_ARCHIVE := $(EXAMPLE_ARCHIVE)
example-lint: export PLATFORM := $(PLATFORM)
example-lint:
	@if test ! -e "$$EXAMPLE_ARCHIVE" && test ! -L "$$EXAMPLE_ARCHIVE"; then $(MAKE) example-image; fi
	./envscout lint --source oci-archive --platform "$$PLATFORM" --profile container-distroless "$$EXAMPLE_ARCHIVE"

test-pixi: native-pixi
	CGO_ENABLED=1 CGO_LDFLAGS="-L$(PIXI_NATIVE_LIB_DIR) $(CGO_LDFLAGS)" go test -tags pixi -modfile=go.pixi.mod ./...

test-race:
	go test -race ./...

vet:
	go vet ./...

lint:
	golangci-lint run ./...

fmt:
	gofmt -w cmd internal

fmt-check:
	@test -z "$$(gofmt -l cmd internal)" || { gofmt -l cmd internal; exit 1; }

mod-tidy:
	go mod tidy

actionlint:
	actionlint .github/workflows/ci.yml .github/workflows/lint.yml
