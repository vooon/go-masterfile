// SPDX-License-Identifier: Apache-2.0

package masterfile

import (
	"iter"
	"strings"
)

// Fqdn returns name with a trailing dot added if it has none. An empty name
// becomes the root ".".
func Fqdn(name string) string {
	if isAbsolute(name) {
		return name
	}
	return name + "."
}

// isAbsolute reports whether name ends with an unescaped dot.
func isAbsolute(name string) bool {
	return strings.HasSuffix(name, ".") && !escapedAt(name, len(name)-1)
}

// escapedAt reports whether the byte at index i is preceded by an odd number
// of backslashes, i.e. is escaped.
func escapedAt(s string, i int) bool {
	n := 0
	for i--; i >= 0 && s[i] == '\\'; i-- {
		n++
	}
	return n%2 == 1
}

// NameEqual compares two names case-insensitively for ASCII letters only
// (RFC 4343); every other byte must match exactly. No normalisation is
// applied: "www" and "www." differ.
func NameEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range len(a) {
		if lowerASCII(a[i]) != lowerASCII(b[i]) {
			return false
		}
	}
	return true
}

func lowerASCII(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + 'a' - 'A'
	}
	return c
}

// upperASCII upper-cases the ASCII letters of s and leaves every other byte
// as it is (RFC 4343: no Unicode folding, so "ı" never becomes "I" and raw
// bytes above 0x7F survive). It returns s itself when nothing changes.
func upperASCII(s string) string { return mapASCII(s, 'a', 'z', 'A'-'a') }

// foldASCII lower-cases the ASCII letters of s, see [upperASCII].
func foldASCII(s string) string { return mapASCII(s, 'A', 'Z', 'a'-'A') }

func mapASCII(s string, lo, hi byte, delta int) string {
	for i := range len(s) {
		if s[i] < lo || s[i] > hi {
			continue
		}
		b := []byte(s)
		for j := i; j < len(b); j++ {
			if b[j] >= lo && b[j] <= hi {
				b[j] = byte(int(b[j]) + delta)
			}
		}
		return string(b)
	}
	return s
}

// Relative returns the part of the absolute name under the absolute origin:
// the origin itself gives "@", "www.example.org." under "example.org." gives
// "www". A name that is "@", not absolute, or not under the origin is
// returned unchanged. The origin must match on a label boundary: an escaped
// dot is not a boundary, and "myexample.org." is not under "example.org.".
// Under the root origin "." an absolute name loses its trailing dot, unless
// that would leave another one (".." stays as it is).
func Relative(name, origin string) string {
	if name == "@" || origin == "" || !isAbsolute(name) {
		return name
	}
	origin = Fqdn(origin)
	if origin == "." {
		if name == "." {
			return "@"
		}
		if r := name[:len(name)-1]; !isAbsolute(r) {
			return r
		}
		return name // "..": stripping would change the name's meaning
	}
	if NameEqual(name, origin) {
		return "@"
	}
	if rel, ok := underOrigin(name, origin); ok {
		return rel
	}
	return name
}

// underOrigin reports whether name is strictly below origin (both absolute)
// on a label boundary and returns the relative part. An escaped dot is not
// a boundary.
func underOrigin(name, origin string) (string, bool) {
	cut := len(name) - len(origin) - 1
	if cut < 1 || name[cut] != '.' || escapedAt(name, cut) || !NameEqual(name[cut+1:], origin) {
		return "", false
	}
	return name[:cut], true
}

// InZone reports whether name is the apex or lies below it, both taken as
// absolute names and compared with [NameEqual] on a label boundary:
// "www.example.org." is in "example.org.", "myexample.org." is not.
func InZone(name, apex string) bool {
	name, apex = Fqdn(name), Fqdn(apex)
	if NameEqual(name, apex) {
		return true
	}
	if apex == "." {
		return true
	}
	_, ok := underOrigin(name, apex)
	return ok
}

// LongestZone returns the apex among apexes that contains name (see
// [InZone]) and has the most labels, so the most specific zone wins. ok is
// false when no apex contains the name.
func LongestZone(name string, apexes []string) (apex string, ok bool) {
	best := -1
	for _, a := range apexes {
		if !InZone(name, a) {
			continue
		}
		if n := labelCount(a); n > best {
			apex, best, ok = a, n, true
		}
	}
	return apex, ok
}

// labelCount counts the labels of a name, splitting on unescaped dots and
// ignoring the root.
func labelCount(name string) int {
	n := 0
	for label := range labels(Fqdn(name)) {
		if label != "" {
			n++
		}
	}
	return n
}

// labels iterates over the labels of name, split on unescaped dots. The
// text after a trailing dot is yielded as an empty label.
func labels(name string) iter.Seq[string] {
	return func(yield func(string) bool) {
		start := 0
		for i := 0; i <= len(name); i++ {
			if i < len(name) && (name[i] != '.' || escapedAt(name, i)) {
				continue
			}
			if !yield(name[start:i]) {
				return
			}
			start = i + 1
		}
	}
}

// Absolute resolves name against origin: "@" is the origin, an absolute
// name is itself, and any other name is appended to the origin. With an
// empty origin a relative name is taken as absolute (a trailing dot is
// added), which is what the reference parser does; "@" then resolves to "".
func Absolute(name, origin string) string {
	switch {
	case name == "@":
		if origin == "" {
			return ""
		}
		return Fqdn(origin)
	case isAbsolute(name):
		return name
	case origin == "" || origin == ".":
		return name + "."
	default:
		return name + "." + Fqdn(origin)
	}
}
