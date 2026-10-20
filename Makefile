.PHONY: build build-pixi native-pixi build-linux build-darwin build-windows image-archive test test-pixi test-race vet lint fmt fmt-check mod-tidy actionlint

IMAGE ?=
PLATFORM ?= linux/amd64
ARCHIVE ?= bin/image.tar
SKOPEO ?= skopeo

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
