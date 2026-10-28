// SPDX-License-Identifier: Apache-2.0

package masterfile

import (
	"strconv"
	"strings"
	"time"
)

// now is replaced in tests.
var now = time.Now

const (
	serialPrefix = "; serial  "
	unixLayout   = "Mon, 02 Jan 2006 15:04:05 UTC"
	dateLayout   = "Mon, 02 Jan 2006 #"
)

// serialKind classifies a serial string.
type serialKind int

const (
	serialOther serialKind = iota // not a 32-bit number: written back unchanged
	serialUnix                    // seconds since the epoch
	serialDate                    // YYYYMMDDnn
)

// classifySerial returns the kind of s and its value when numeric. A serial
// is a date serial when it lies in 1990010100..2099123199 and its first
// eight digits form a valid calendar date; any other number is a Unix time.
func classifySerial(s string) (serialKind, uint32) {
	n, err := strconv.ParseUint(s, 10, 32) // digits only: no sign, no underscore

	if err != nil {
		return serialOther, 0
	}
	if n >= 1990010100 && n <= 2099123199 {
		if _, err := time.Parse("20060102", s[:8]); err == nil {
			return serialDate, uint32(n)
		}
	}
	return serialUnix, uint32(n)
}

// Increase returns the serial to write after a change: a Unix time serial
// becomes max(now, serial+1); a date serial is incremented by one with no
// date logic ("2024123199" becomes "2024123200"). Anything else is returned
// unchanged. Two bumps within one second still increase.
func Increase(serial string) string {
	kind, n := classifySerial(serial)
	switch kind {
	case serialUnix:
		next := uint64(n) + 1
		if t := now().Unix(); t > 0 && uint64(t) > next {
			next = uint64(t)
		}
		return strconv.FormatUint(next, 10)
	case serialDate:
		return strconv.FormatUint(uint64(n)+1, 10)
	}
	return serial
}

// renderSerial returns the human rendering of a serial for the generated
// comment, or "" for a non-numeric serial.
func renderSerial(serial string) string {
	kind, n := classifySerial(serial)
	switch kind {
	case serialUnix:
		return time.Unix(int64(n), 0).UTC().Format(unixLayout)
	case serialDate:
		t, _ := time.Parse("20060102", serial[:8])
		return t.Format(dateLayout) + serial[8:]
	}
	return ""
}

// serialComment builds the generated serial comment for serial, keeping the
// user part of the existing comment (if any) after it.
func serialComment(serial, existing string) string {
	c := strings.TrimRight(serialPrefix+renderSerial(serial), " ")
	if user := UserComment(existing); user != "" {
		c += " " + user
	}
	return c
}

// UserComment returns the user-written part of a serial comment generated
// by this package: "; serial  <rendering> ; note" gives "; note" and a
// comment holding only the generated text gives "". Any other comment is
// returned unchanged. Verification uses it so that regenerated renderings
// do not count as lost comments.
func UserComment(c string) string {
	if c == strings.TrimRight(serialPrefix, " ") {
		return ""
	}
	rest, ok := strings.CutPrefix(c, serialPrefix)
	if !ok {
		return c
	}
	switch {
	case len(rest) >= len(dateLayout)+2 && isDigit(rest[len(dateLayout)]) && isDigit(rest[len(dateLayout)+1]):
		if _, err := time.Parse(dateLayout, rest[:len(dateLayout)]); err == nil {
			return strings.TrimLeft(rest[len(dateLayout)+2:], " ")
		}
	case len(rest) >= len(unixLayout):
		if _, err := time.Parse(unixLayout, rest[:len(unixLayout)]); err == nil {
			return strings.TrimLeft(rest[len(unixLayout):], " ")
		}
	}
	return c
}
