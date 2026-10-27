# envscout

**Discovery, inventory, and linting** for Python and conda environments and container-images.

> [!NOTE]
> Experimental software under incubation.

Building requires Go 1.26.8+, Rust/Cargo, Make, and a C compiler.

```sh
make build
./envscout find
./envscout find --format json
./envscout find /path/to/environments
./envscout scan /path/to/environments
./envscout scan --format json --output-dir /path/to/reports /path/to/environments
./envscout lint /path/to/environments
./envscout lint --list-rules
./envscout --help
```

SBOMs go to `./sboms/` unless `--output-dir` selects another directory; existing files are never overwritten. Pixi environments also show a lock summary when available.

All commands support `--format text|json` and `--no-color`. Only `scan` accepts `--output-dir`. Flags may precede or follow the subcommand. Ctrl-C cancels the command.

Without roots, `find` checks known installation and configuration locations; it does not search the whole filesystem.

Explicit-root searches do not follow symlinks or cross filesystem-device boundaries. They skip `.git`, `node_modules`, `__pycache__`, `site-packages`, and conda package caches unless those paths are supplied as roots. Scans run offline and retain successful SBOMs when other environments cannot be inspected.

For OCI archives, specify a platform:

```sh
./envscout lint --source oci-archive --platform linux/amd64 --profile container-runtime image.tar
```

Use `--format json` for CI. Lint writes no SBOMs. Lint exit codes are 0 (below threshold), 1 (policy findings), 2 (input/inspection failure), and 130 (cancelled).

Run `make example-lint` for the container demo; Docker Buildx and network access are required. A lint failure is expected. `make lint-demo` runs offline fixtures without Docker.

Only scan trusted image archives; envscout is not a sandbox. Windows output inherits filesystem ACLs, so choose a restricted location for sensitive reports.

## Built with

* [fastwalk](https://github.com/charlievieth/fastwalk) for fast directory traversal
* [stereoscope](https://github.com/anchore/stereoscope) for processing container images
* [syft](https://github.com/anchore/syft) for SBOM generation
* [go-rattler](https://github.com/conda-incubator/go-rattler) for conda domain specific functions through [rattler](https://github.com/conda/rattler)
* [cobra](https://github.com/spf13/cobra) for a modern Go CLI experience

Licensed under BSD-3-Clause.
