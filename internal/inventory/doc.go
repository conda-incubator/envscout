// Package inventory catalogs selected sources offline through Syft and writes
// CycloneDX JSON SBOMs without overwriting existing files. Directory sources are
// owned and closed; image sources borrow caller-owned stereoscope images.
// CondaRecords validates metadata without running unrelated package catalogers;
// ParseCondaRecord shares pure document parsing with bounded evidence readers.
// OwnershipIndex tracks ambiguity only for paths admitted by its caller.
package inventory
