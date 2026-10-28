// SPDX-License-Identifier: Apache-2.0

package masterfile

import "strings"

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
	cut := len(name) - len(origin) - 1
	if cut < 1 || name[cut] != '.' || escapedAt(name, cut) || !NameEqual(name[cut+1:], origin) {
		return name
	}
	return name[:cut]
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
