// SPDX-License-Identifier: Apache-2.0

package masterfile

import "strings"

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
		if o, ok := originName(e); ok {
			s.origin = o
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

// originName returns the origin a $ORIGIN directive puts in force, as an
// absolute name in the written (escaped) form that owners use, so that an
// escaped dot or blank in it stays escaped when the origin is written back
// as an owner. ok is false for any other entry.
func originName(e Entry) (name string, ok bool) {
	if e.kind != Directive || e.name != "$ORIGIN" || len(e.args) == 0 {
		return "", false
	}
	return Fqdn(nameText(e.args[0])), true
}

// nameText returns a field as an unquoted name. An unquoted field is one
// already. A quoted one loses its quotes, and the bytes that would end an
// unquoted item (blanks, ";", parentheses) get a backslash; escapes inside
// it are kept as written.
func nameText(f Field) string {
	if !f.Quoted || len(f.Raw) < 2 {
		return f.Raw
	}
	inner := f.Raw[1 : len(f.Raw)-1]
	var b strings.Builder
	b.Grow(len(inner))
	for i := 0; i < len(inner); i++ {
		switch c := inner[i]; c {
		case '\\':
			b.WriteByte(c)
			if i++; i < len(inner) {
				b.WriteByte(inner[i])
			}
		case ' ', '\t', ';', '(', ')':
			b.WriteByte('\\')
			b.WriteByte(c)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
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
		if e.kind == Record && e.rtype == typeSOA {
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
		if o, ok := originName(e); ok {
			return o, true
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
	form := formUnknown
	for i := range entries {
		e := &entries[i]
		abs := st.step(*e)
		if e.kind != Record {
			continue
		}
		if e.owner != "" {
			form = e.form
		}
		e.form = form // an inherited owner is spelled like the one it repeats
		if abs == "" {
			e.owner = ""
			continue
		}
		e.owner = Relative(abs, apex)
	}
}
