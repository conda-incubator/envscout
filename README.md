# envscout

**Discovery, inventory, and advice** for Python and conda environments.

Experimental; advice is planned, not implemented.

```sh
make build
./envscout find
./envscout scan /path/to/environments
./envscout --help
```

Use `make build-pixi` for rattler support (requires Rust/Cargo and a C compiler). SBOMs go to `./sboms/`; existing files are not overwritten.

Only scan trusted image archives; envscout is not a sandbox. Windows output inherits filesystem ACLs, so choose a restricted location for sensitive reports.

Licensed under BSD-3-Clause.
