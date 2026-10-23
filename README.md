# envscout

**Discovery, inventory, and advice** for Python and conda environments.

Experimental; evidence-based advice is available through the separate `lint` command.

```sh
make build
./envscout find
./envscout find --format json
./envscout scan /path/to/environments
./envscout scan --format json --output-dir /path/to/reports /path/to/environments
./envscout lint /path/to/environments
./envscout lint --list-rules
./envscout --help
```

Build with Go 1.26+, Rust/Cargo, and a C compiler. go-rattler is always linked through cgo; its Rust static library is built from the exact dependency pinned in `go.mod`. `make build`, `make test`, `make test-race`, `make vet`, and `make lint` prepare that library and set the linker path. There is one build configuration, with no Pixi feature tag or alternate modfile. `go build` alone does not run Cargo.

Native output is cached in `.go-rattler-native/`; no separate rattler library is needed at runtime. Cross-compilation requires a matching Rust target and C toolchain, not `CGO_ENABLED=0`. Scanning uses syft and stereoscope in-process; no external `syft` executable is needed.

On Windows amd64, use an MSYS2 MinGW-w64 shell, install Rust's `x86_64-pc-windows-gnu` target, and run `CARGO_BUILD_TARGET=x86_64-pc-windows-gnu CC=gcc make build`. The MSVC Rust target is not compatible with the cgo toolchain. CI uses the GNU target too.

SBOMs go to `./sboms/` unless `--output-dir` selects another directory; existing files are not overwritten. Prefixes with a readable Pixi marker include a rattler-derived lock summary in scan output.

All commands share `--format text|json`, `--no-color`, `--source dir|oci-archive`, and `--platform OS/ARCH[/VARIANT]`. Image sources require a platform; directory sources reject it. Only `scan` accepts `--output-dir`. Use `--format json`, not the removed `--json` flag. Flags may precede or follow the subcommand. Invalid flags exit 2. Ctrl-C cancels any command (exit 130); a second interrupt forces termination.

Host discovery in text mode shows folders scanned and environments found on terminal stderr, refreshed at most five times per second. Redirected stderr, JSON mode, image sources, and `TERM=dumb` disable the display and its counters. Discovery workers never print or make extra filesystem calls for progress.

`find` without roots checks a bounded set of installation paths, conda/Pixi environment variables, `~/.conda/environments.txt`, user-level `.condarc` `envs_dirs`, and local Pixi environments. Configured paths support home/environment-variable expansion. These are discovery hints, not a complete implementation of conda configuration precedence.

Explicit-root walks do not follow symlinks or cross filesystem-device boundaries. Default traversal skips `.git`, `node_modules`, `__pycache__`, `site-packages`, and confirmed conda package caches. Explicitly supplied roots are still searched inside excluded subtrees. These exclusions trade exhaustive recall for faster discovery.

A candidate needs a `conda-meta` directory with at least one regular, non-symlink `.json` file. `find` does not parse package-record content. Scanning and linting validate records; malformed records are inventory/evidence problems, not proof of an installed package. Directory and image scans use the same offline configuration, with no remote license lookups or host language-package caches. Partial scans retain successful SBOMs and report invalid or unreadable metadata as incomplete.

For OCI archives: `./envscout lint --source oci-archive --platform linux/amd64 --profile container-runtime image.tar`. Use `--format json` for CI; exit codes are 0 (below threshold), 1 (policy findings), 2 (input/inspection failure), and 130 (cancelled). Lint creates no SBOMs. Pixi hash and manifest-sync verification remain unavailable; package counts are not a sync check.

Run `make example-lint` for the deliberately bloated `examples/Dockerfile` demo (policy failure is expected). It builds the OCI archive if missing and otherwise reuses it; set `EXAMPLE_ARCHIVE=bin/demo.tar` to change the path. Building requires Docker Buildx and network access, with a temporary builder unless `BUILDER=NAME` selects an existing one. Offline fixtures in `make lint-demo` do not require Docker.

Only scan trusted image archives; envscout is not a sandbox. Windows output inherits filesystem ACLs, so choose a restricted location for sensitive reports.

Licensed under BSD-3-Clause.
