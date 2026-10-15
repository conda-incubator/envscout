.PHONY: build build-pixi native-pixi build-linux build-darwin build-windows test test-pixi test-race vet lint fmt fmt-check mod-tidy actionlint

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
