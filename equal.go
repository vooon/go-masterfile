// SPDX-License-Identifier: Apache-2.0

package masterfile

import "slices"

// Equal compares two entries literally: same kind, and for records the same
// owner (ASCII case-insensitive), class, type, decoded values and the same
// explicit TTL in seconds (or both absent). Comments and the written form
// of values are ignored. Directives compare by name and decoded arguments;
// comment entries by text.
func (e Entry) Equal(o Entry) bool {
	if e.kind != o.kind {
		return false
	}
	switch e.kind {
	case Blank:
		return true
	case Comment:
		return e.comment == o.comment
	case Directive:
		return e.name == o.name && directiveValuesEqual(e.name, e.Values(), o.Values())
	}
	if e.hasTTL != o.hasTTL || (e.hasTTL && e.ttl.Seconds != o.ttl.Seconds) {
		return false
	}
	return e.sameRecord(o)
}

// directiveValuesEqual compares directive arguments by meaning: $TTL by
// seconds, $ORIGIN by name, anything else literally.
func directiveValuesEqual(name string, a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	if len(a) == 0 {
		return true
	}
	switch name {
	case "$TTL":
		x, okx := StringToTTL(a[0])
		y, oky := StringToTTL(b[0])
		return okx && oky && x == y && slices.Equal(a[1:], b[1:])
	case "$ORIGIN":
		return NameEqual(Fqdn(a[0]), Fqdn(b[0])) && slices.Equal(a[1:], b[1:])
	}
	return slices.Equal(a, b)
}

// sameRecord compares records ignoring TTL and comments.
func (e Entry) sameRecord(o Entry) bool {
	return NameEqual(e.owner, o.owner) &&
		e.classOrDefault() == o.classOrDefault() &&
		e.rtype == o.rtype &&
		slices.Equal(e.Values(), o.Values())
}

func (e Entry) classOrDefault() string {
	if e.class == "" {
		return "IN"
	}
	return e.class
}

// ttlState tracks the $TTL in force while walking entries.
type ttlState struct {
	seconds uint32
	known   bool
}

// apply updates the state from a $TTL directive.
func (s *ttlState) apply(e Entry) {
	if e.kind == Directive && e.name == "$TTL" && len(e.args) > 0 {
		if secs, ok := StringToTTL(e.args[0].Value); ok {
			s.seconds, s.known = secs, true
		}
	}
}

// effective returns the record's effective TTL: its own if present, else
// the $TTL in force; known is false when neither exists.
func (s ttlState) effective(e Entry) (uint32, bool) {
	if e.hasTTL {
		return e.ttl.Seconds, true
	}
	return s.seconds, s.known
}

// EntriesEqual compares two entry lists by meaning: same length, pairwise
// [Entry.Equal] ignoring explicit TTLs, and equal effective TTLs for records
// (both unknown is equal; known versus unknown is not). It is the test for
// whether an edit changed anything.
func EntriesEqual(a, b []Entry) bool {
	if len(a) != len(b) {
		return false
	}
	var sa, sb ttlState
	for i := range a {
		x, y := a[i], b[i]
		sa.apply(x)
		sb.apply(y)
		if x.kind != Record || y.kind != Record {
			if !x.Equal(y) {
				return false
			}
			continue
		}
		if !x.sameRecord(y) {
			return false
		}
		tx, kx := sa.effective(x)
		ty, ky := sb.effective(y)
		if kx != ky || (kx && tx != ty) {
			return false
		}
	}
	return true
}
