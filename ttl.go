// SPDX-License-Identifier: Apache-2.0

package masterfile

import "math"

// TTL is a time-to-live as written in a zone file together with its value
// in seconds.
type TTL struct {
	Raw     string // as written, e.g. "1h" or "3600"
	Seconds uint32
}

// StringToTTL parses a TTL: a decimal number of seconds, or a BIND duration
// made of <digits><unit> parts with units s, m, h, d and w in any case,
// optionally ending in bare digits (seconds), such as "1h30m", "2W" or "90".
// The value must fit in 32 bits. It reports false for anything else,
// including an empty string.
func StringToTTL(s string) (uint32, bool) {
	if s == "" {
		return 0, false
	}
	var total uint64
	i := 0
	for i < len(s) {
		start := i
		var n uint64
		for i < len(s) && isDigit(s[i]) {
			n = n*10 + uint64(s[i]-'0')
			if n > math.MaxUint32 {
				return 0, false
			}
			i++
		}
		if i == start {
			return 0, false // unit without digits, or a stray byte
		}
		mult := uint64(1)
		if i < len(s) {
			switch s[i] {
			case 's', 'S':
			case 'm', 'M':
				mult = 60
			case 'h', 'H':
				mult = 3600
			case 'd', 'D':
				mult = 86400
			case 'w', 'W':
				mult = 7 * 86400
			default:
				return 0, false
			}
			i++
		}
		total += n * mult
		if total > math.MaxUint32 {
			return 0, false
		}
	}
	return uint32(total), true
}
