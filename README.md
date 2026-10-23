# envscout

**Discovery, inventory, and advice** for Python and conda environments.

Experimental; evidence-based advice is available through the separate `lint` command.

```sh
make build
./envscout find
./envscout scan /path/to/environments
./envscout lint /path/to/environments
./envscout lint --list-rules
./envscout --help
```

Use `make build-pixi` for rattler support (requires Rust/Cargo and a C compiler). SBOMs go to `./sboms/`; existing files are not overwritten.

For OCI archives: `./envscout lint --source oci-archive --platform linux/amd64 --profile container-runtime image.tar`. Use `--format json` for CI; exit codes are 0 (below threshold), 1 (policy findings), 2 (input/inspection failure), and 130 (cancelled). Lint creates no SBOMs. Pixi hash and manifest-sync verification remain unavailable; package counts are not a sync check.

Run `make example-lint` for the deliberately bloated `examples/Dockerfile` demo (policy failure is expected). It builds the OCI archive if missing and otherwise reuses it; set `EXAMPLE_ARCHIVE=bin/demo.tar` to change the path. Building requires Docker Buildx and network access, with a temporary builder unless `BUILDER=NAME` selects an existing one. Offline fixtures in `make lint-demo` do not require Docker.

Only scan trusted image archives; envscout is not a sandbox. Windows output inherits filesystem ACLs, so choose a restricted location for sensitive reports.

Licensed under BSD-3-Clause.
