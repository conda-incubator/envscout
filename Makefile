.PHONY: build image-archive example-image example-lint lint-demo test test-race vet lint fmt fmt-check mod-tidy actionlint native tmp-dir
.DEFAULT_GOAL := build

IMAGE ?=
PLATFORM ?= linux/amd64
ARCHIVE ?= bin/image.tar
SKOPEO ?= skopeo
EXAMPLE_ARCHIVE ?= bin/lint-example.tar
BUILDER ?=

# go-rattler is the pinned Rust-backed dependency. Its source comes from the
# module cache, and its static archive is built into a writable target directory.
RATTLER_MODULE = github.com/conda-incubator/go-rattler
RATTLER_TARGET_DIR = $(abspath .go-rattler-native)
TMP_DIR = $(abspath .tmp)
BINARY ?= envscout

# Cargo writes to <target>/<CARGO_BUILD_TARGET>/release when a target is set,
# otherwise <target>/release. Windows GNU builds set CARGO_BUILD_TARGET so the
# MinGW archive does not collide with a host archive.
NATIVE_LIB_DIR = $(RATTLER_TARGET_DIR)/$(if $(CARGO_BUILD_TARGET),$(CARGO_BUILD_TARGET)/)release

# Windows cgo runs MinGW gcc/ld and Go's own linker, which need a drive-letter
# path (C:/...) rather than an MSYS /c/... path. cygpath -m emits that form.
ifeq ($(OS),Windows_NT)
RATTLER_TARGET_DIR := $(shell cygpath -m "$(RATTLER_TARGET_DIR)")
# testing.TempDir preserves its parent spelling; use native separators.
TMP_DIR := $(shell cygpath -w "$(TMP_DIR)")
BINARY := envscout.exe
endif

# Exported so every go command (build, test, vet, lint) sees the same cgo
# settings. Caller-provided CGO_LDFLAGS are preserved after the library path.
export CGO_ENABLED := 1
export CGO_LDFLAGS := -L "$(NATIVE_LIB_DIR)" $(CGO_LDFLAGS)

# Keep tool scratch files and testing.TempDir inside this worktree on every OS.
export GOTMPDIR := $(TMP_DIR)
export TMPDIR := $(TMP_DIR)
export TMP := $(TMP_DIR)
export TEMP := $(TMP_DIR)

tmp-dir:
	@mkdir -p "$(TMP_DIR)"

# Builds the go-rattler static archive from the pinned module source.
# Shared prerequisite: make runs it once per invocation even when several
# targets (build test vet lint) are requested together.
native: | tmp-dir
	@set -eu; \
	  go mod download $(RATTLER_MODULE); \
	  source_dir="$$(go list -m -f '{{.Dir}}' $(RATTLER_MODULE))"; \
	  test -n "$$source_dir" || { echo 'go-rattler module source not found' >&2; exit 1; }; \
	  CARGO_TARGET_DIR="$(RATTLER_TARGET_DIR)" cargo build --manifest-path "$$source_dir/internal/native/Cargo.toml" --release --locked

build: native
	go build -o "$(BINARY)" ./cmd/envscout

test: native
	go test ./...

test-race: native
	go test -race ./...

vet: native
	go vet ./...

lint: native
	golangci-lint run ./...

lint-demo: native
	go test -count=1 -v ./internal/cli -run '^TestLintImageMultipleRulesAndLayerRetention$$'

# Pass user values through the environment, not as shell source.
image-archive: export IMAGE := $(IMAGE)
image-archive: export PLATFORM := $(PLATFORM)
image-archive: export ARCHIVE := $(ARCHIVE)
image-archive: export SKOPEO := $(SKOPEO)
image-archive: | tmp-dir
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

example-image: export EXAMPLE_ARCHIVE := $(EXAMPLE_ARCHIVE)
example-image: export PLATFORM := $(PLATFORM)
example-image: export BUILDER := $(BUILDER)
example-image: | tmp-dir
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
example-lint: build
	@if test ! -e "$$EXAMPLE_ARCHIVE" && test ! -L "$$EXAMPLE_ARCHIVE"; then $(MAKE) example-image; fi
	./envscout lint --source oci-archive --platform "$$PLATFORM" --profile container-distroless "$$EXAMPLE_ARCHIVE"

fmt: | tmp-dir
	gofmt -w cmd internal

fmt-check: | tmp-dir
	@test -z "$$(gofmt -l cmd internal)" || { gofmt -l cmd internal; exit 1; }

mod-tidy: | tmp-dir
	go mod tidy

actionlint: | tmp-dir
	actionlint .github/workflows/ci.yml .github/workflows/lint.yml
