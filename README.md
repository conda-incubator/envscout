# envscout

**Discovery, inventory, and linting** for Python and conda environments and container-images.

> [!NOTE]
> Experimental software under incubation.

Building requires Go 1.26.8+, Rust/Cargo, Make, and a C compiler.

```sh
make build
source <(./envscout completion zsh)
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

Existing regular SBOM files are counted as pre-existing, left untouched and not rescanned; they do not cause a failure exit. JSON marks them with `pre_existing: true`. Their contents and freshness are not verified. Symlink or directory collisions and genuine scan errors still fail.

All commands support `--format text|json` and `--no-color`. Only `scan` accepts `--output-dir`. Flags may precede or follow the subcommand. Ctrl-C cancels the command.

Interactive text scans and lint runs show discovery progress followed by work counts, a spinner, approximate remaining time and iterations/sec. Estimates use successful new scans or lint evidence passes, excluding discovery, prior lint validation, pre-existing skips and failures, and show "estimating" until a sample is available. Environment sizes and unfinished skips can change the estimate. JSON and redirected output have no live progress display.

Without roots, `find` checks known installation and configuration locations; it does not search the whole filesystem.

Directory `find` summarizes unreadable paths without failing; use `--verbose` for individual warnings. JSON output always includes the issue details.

Local `find` and `scan` recognize conda prefixes and virtualenvs with a `pyvenv.cfg` marker, including those created by uv, Poetry, virtualenv or `python -m venv`. Scans cover the selected prefix, not inherited system packages or external editable-install sources; empty virtualenvs are valid. Virtualenv linting is not yet supported and reports incomplete inspection (exit 2). OCI environment discovery remains conda-only.

Explicit-root searches do not follow symlinks or cross filesystem-device boundaries. They skip `.git`, `node_modules`, `__pycache__`, `site-packages`, and conda package caches unless those paths are supplied as roots. Scans run offline and retain successful SBOMs when other environments cannot be inspected.

All three commands accept repeatable folder globs, for example `./envscout lint --rule ENV013 --exclude '.cache' --exclude '**/build' ~/`. Quote patterns; bare names match at any depth, `/` patterns are search-root relative (current directory for no-root `find`, `/` for images), and absolute paths also work. Matches are case-sensitive and skip entire subtrees, including explicit roots.

Exclusions apply only to discovery, not package files inside selected environments or whole-image SBOMs/image-wide lint evidence.

On macOS, [Transparency, Consent, and Control (TCC)](https://developer.apple.com/forums/thread/678819) can show a Files and Folders consent dialog for protected locations such as Documents, Desktop and Downloads. [Folder access can block until you respond](https://developer.apple.com/forums/thread/126430); approve access to continue, or use `--exclude 'Documents'` (repeatable) to avoid those folders during discovery. Exclusions do not prevent prompts from later access inside selected environments.

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
