// SPDX-License-Identifier: Apache-2.0

package masterfile

// originState walks entries tracking the $ORIGIN in force and the last
// explicit owner, resolving every record's owner to an absolute name.
type originState struct {
	origin    string
	lastOwner string // absolute owner of the previous record, "" if none
}

// step updates the state for e and returns the record's absolute owner, or
// "" when it has none to inherit.
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

// startOrigin is the origin in force before any $ORIGIN line: the hint, or
// the root when there is none, under which a relative name is taken as
// absolute and "@" is the root itself (what the reference parser does).
func startOrigin(hint string) string {
	if hint == "" {
		return "."
	}
	return Fqdn(hint)
}

// findApex returns the apex of the entries: the owner of the first SOA
// record resolved against the $ORIGIN in force (startOrigin before any
// $ORIGIN). Without an SOA, or with one whose owner cannot be determined
// ("@" with no origin), the apex is the hint made absolute, else the first
// $ORIGIN, else the root, and known is false in that last case only.
func findApex(entries []Entry, hint string) (apex string, known bool) {
	st := originState{origin: startOrigin(hint)}
	for i := range entries {
		e := &entries[i]
		owner := st.step(*e)
		if e.kind == Record && e.typ == "SOA" {
			if owner != "" && (hint != "" || owner != ".") {
				return owner, true
			}
			break
		}
	}
	if hint != "" {
		return Fqdn(hint), true
	}
	for _, e := range entries {
		if e.kind == Directive && e.name == "$ORIGIN" && len(e.args) > 0 {
			return Fqdn(e.args[0].Value), true
		}
	}
	return ".", false
}

// resolveOwners rewrites every record so that its owner is explicit and
// relative to apex: "@" for the apex, "www" for www.<apex>, the absolute
// name for anything outside the apex. Names are resolved against the
// $ORIGIN in force (startOrigin(hint) before any $ORIGIN line), never
// against the apex itself: a file without origin whose SOA owner is "0"
// has the apex "0." and that record becomes "@", not "0.0.". Inherited
// (blank) owners are filled from the previous record; a record with
// nothing to inherit is left ownerless. Afterwards an entry's meaning no
// longer depends on its position or on $ORIGIN lines.
func resolveOwners(entries []Entry, hint, apex string) {
	st := originState{origin: startOrigin(hint)}
	for i := range entries {
		e := &entries[i]
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
}
