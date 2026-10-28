// SPDX-License-Identifier: Apache-2.0

package masterfile

import "fmt"

// originState walks entries tracking the $ORIGIN in force and the last
// explicit owner, resolving every record's owner to an absolute name.
type originState struct {
	origin    string
	lastOwner string // absolute owner of the previous record, "" if none
}

// step updates the state for e and returns the record's absolute owner, or
// "" when it has none to inherit. apply reports whether e changed state.
func (s *originState) step(e Entry) string {
	switch e.kind {
	case Directive:
		if e.name == "$ORIGIN" && len(e.args) > 0 {
			s.origin = Fqdn(e.args[0].Value)
		}
		return ""
	case Record:
		if e.owner != "" {
			s.lastOwner = Absolute(e.owner, s.origin)
		}
		return s.lastOwner
	}
	return ""
}

// Origin returns the apex of the file: the owner of the first SOA record,
// resolved against the $ORIGIN in force (the hint before any $ORIGIN),
// together with that record. Without an SOA the apex is the first $ORIGIN,
// else the hint made absolute, else ""; the record is then nil. A bare "@"
// SOA owner with no origin at all yields "".
func (f *File) Origin(hint string) (string, *Entry) {
	st := originState{}
	if hint != "" {
		st.origin = Fqdn(hint)
	}
	for i := range f.Entries {
		e := &f.Entries[i]
		owner := st.step(*e)
		if e.kind == Record && e.typ == "SOA" {
			return owner, e
		}
	}
	for _, e := range f.Entries {
		if e.kind == Directive && e.name == "$ORIGIN" && len(e.args) > 0 {
			return Fqdn(e.args[0].Value), nil
		}
	}
	if hint == "" {
		return "", nil
	}
	return Fqdn(hint), nil
}

// ResolveOwners rewrites every record so that its owner is explicit and
// relative to apex: "@" for the apex, "www" for www.<apex>, the absolute
// name for anything outside the apex. Inherited (blank) owners are filled
// from the previous record; a record with nothing to inherit is left
// ownerless. Afterwards an entry's meaning no longer depends on its
// position or on $ORIGIN lines. It fails when "@" is used with no origin
// known.
func (f *File) ResolveOwners(apex string) error {
	st := originState{origin: apex}
	if apex != "" {
		st.origin = Fqdn(apex)
	}
	for i := range f.Entries {
		e := &f.Entries[i]
		if e.kind == Record && e.owner == "@" && st.origin == "" {
			return fmt.Errorf("line %d: @ used without an origin", e.line)
		}
		abs := st.step(*e)
		if e.kind != Record {
			continue
		}
		if abs == "" {
			e.owner = ""
			continue
		}
		e.owner = Relative(abs, apex)
	}
	return nil
}
