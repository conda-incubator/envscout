// Package discovery locates conda prefixes and pyvenv.cfg-marked virtualenvs without
// executing interpreters or parsing package records.
// Host searches are bounded known-location probes or non-symlink, same-device walks
// of explicit roots with documented directory exclusions. Images use the final
// squashed filesystem, never host hints. Optional history supplies a zero-based
// conda revision; Issues describe incomplete inspection, not a clean bill of health.
package discovery
