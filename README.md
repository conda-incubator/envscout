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

For OCI archives: `./envscout lint --source oci-archive --platform linux/amd64 --profile container-runtime image.tar`. Use `--format json` for CI; exit codes are 0 (below threshold), 1 (policy findings), 2 (input/inspection failure), and 130 (cancelled). Lint writes no SBOM files. It uses canonical go-rattler records and offline Python cataloging for local package checks. ENV010 compares installed conda metadata with the Pixi marker's selected lock environment and platform. It does not verify PyPI packages, installed files, Pixi's installed-lock hash, or manifest freshness.

Lint JSON report schema is version 4, ruleset version 5, and profile version 3; policy config files remain version 1. `findings` contain instance-specific evidence, messages, severities, fingerprints, and an optional `next` action that overrides the rule's generic recommendation. `lint --list-rules` prints explanations, actions, profiles, documentation links, and limits; add `--format json` for structured rule metadata. `outcomes` includes active checks only; `outcome_counts` also accounts for disabled and not-applicable checks. Match findings to outcomes using `(target, rule_id)`.

Phase 4 renames EC001/EC004/EC002/EC003 to ENV001/ENV002/ENV010/ENV011, and IC001/IC002/IC003/IC004/IC006/IC007 to IMG001/IMG002/IMG003/IMG004/IMG005/IMG006. Old IDs are rejected. Update `--rule`, `--disable-rule`, policy rule keys and suppression IDs. Fingerprints include rule IDs, so regenerate fingerprint suppressions from a new report. Existing path/target selectors still work after updating their rule ID.

ENV013 checks certificate package metadata only (`certifi` and `ca-certificates` `conda-meta` records). It never reads certificate bundle content or Python packages. Minimum versions, verified 2026-10-26 from the official conda package repositories: `certifi` 2026.10.19 and `ca-certificates` 2026.10.20 on `https://repo.anaconda.com/pkgs/main`; `certifi` 2026.10.19 and `ca-certificates` 2026.10.19 on `https://conda.anaconda.org/conda-forge`. A record older than its minimum is a Warning remediation finding, not a vulnerability claim. Records from other or missing channels are Unknown with no findings. Metadata alone does not prove runtime trust, and a package below the minimum may still be the one a prefix actually loads. ENV013 is Warning by default in all profiles and reports one finding per stale package.

Local rules inspect only discovered prefixes under the explicit roots. Duplicate checks compare conda metadata across those prefixes, not pip packages or file contents. Python cataloging indexes direct distribution metadata in recognized `lib/pythonX.Y/site-packages`, `lib64/pythonX.Y/site-packages` and Windows `Lib/site-packages` locations, without traversing application payload trees, arbitrary build workspaces or external `PYTHONPATH` entries. Unowned metadata indicates installation outside conda, not necessarily pip; a version conflict does not prove Python import precedence. Tooling-prefix checks identify extra packages rather than proving application use. ENV008 inspects shared cache roots once per run, measures archive sizes and identifies extracted directories from canonical markers without recursively sizing their payloads. Sizes are not unique or reclaimable disk space. Python EOL follows the dated upstream CPython support table; vendor support can differ. ENV002 requires an explicit `--project` association and checks lockfile presence, not installation synchronization. ENV011 remains unavailable because MatchSpec matching cannot verify Pixi manifest/lock freshness.

Run `make example-lint` for the deliberately bloated `examples/Dockerfile` demo (policy failure is expected). It builds the OCI archive if missing and otherwise reuses it; set `EXAMPLE_ARCHIVE=bin/demo.tar` to change the path. Building requires Docker Buildx and network access, with a temporary builder unless `BUILDER=NAME` selects an existing one. Offline fixtures in `make lint-demo` do not require Docker.

Only scan trusted image archives; envscout is not a sandbox. Windows output inherits filesystem ACLs, so choose a restricted location for sensitive reports.

Licensed under BSD-3-Clause.
