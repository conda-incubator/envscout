# envscout

**Discovery, inventory, and advice** for Python and conda environments.

`envscout find` checks known conda locations without walking your whole home directory. Use `envscout find ROOT...` to walk specific directories completely, or `envscout find --json` to see the search mode, checked hints, and inspection issues. `envscout scan ROOT...` still requires explicit roots and writes one SBOM per confirmed prefix.

Licensed under BSD-3-Clause.
