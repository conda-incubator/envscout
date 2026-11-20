package inventory

// FileOwnership retains the last claimed name and any earlier conflict. An
// ambiguous claim is not proof of ownership, even when Name is nonempty.
type FileOwnership struct {
	Name      string
	Ambiguous bool
}

// OwnershipIndex indexes caller-admitted paths without I/O or path normalization.
type OwnershipIndex map[string]FileOwnership

// Add records a claim in source order. Empty previous names retain the existing
// unknown-owner sentinel behavior; ambiguity remains sticky across later claims.
func (index OwnershipIndex) Add(path, name string) {
	owner := index[path]
	if owner.Name != "" && owner.Name != name {
		owner.Ambiguous = true
	}
	owner.Name = name
	index[path] = owner
}
