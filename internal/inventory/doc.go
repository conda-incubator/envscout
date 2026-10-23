// Package inventory catalogs selected sources offline through Syft and writes
// CycloneDX JSON SBOMs without overwriting existing files. Directory sources are
// owned and closed; image sources borrow caller-owned stereoscope images.
// CondaRecords validates metadata without running unrelated package catalogers.
package inventory
