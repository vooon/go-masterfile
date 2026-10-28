// SPDX-License-Identifier: Apache-2.0

package masterfile

import "strings"

// decodeEscape decodes the escape sequence at the start of s, which must
// begin with a backslash followed by at least one byte. "\DDD" with exactly
// three decimal digits and a value of at most 255 is one byte; otherwise the
// backslash escapes only the next byte. It returns the byte and the number
// of input bytes consumed.
func decodeEscape(s []byte) (byte, int) {
	if len(s) >= 4 && isDigit(s[1]) && isDigit(s[2]) && isDigit(s[3]) {
		v := int(s[1]-'0')*100 + int(s[2]-'0')*10 + int(s[3]-'0')
		if v <= 255 {
			return byte(v), 4
		}
	}
	return s[1], 2
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// Quote renders s as a zone file quoted string: it is wrapped in double
// quotes, '"' and '\' are prefixed with a backslash, and bytes below 0x20
// and byte 0x7F are written as "\DDD". All other bytes, including UTF-8 and
// bytes above 0x7F, are copied. Parsing the result yields exactly s.
func Quote(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 2)
	b.WriteByte('"')
	for i := range len(s) {
		c := s[i]
		switch {
		case c == '"' || c == '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		case c < 0x20 || c == 0x7F:
			b.WriteByte('\\')
			b.WriteByte('0' + c/100)
			b.WriteByte('0' + c/10%10)
			b.WriteByte('0' + c%10)
		default:
			b.WriteByte(c)
		}
	}
	b.WriteByte('"')
	return b.String()
}
