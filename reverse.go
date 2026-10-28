// SPDX-License-Identifier: Apache-2.0

package masterfile

import (
	"net/netip"
	"strconv"
	"strings"
)

const (
	v4Arpa = ".in-addr.arpa."
	v6Arpa = ".ip6.arpa."
)

// ReverseName returns the absolute reverse-lookup name of addr:
// "1.2.0.192.in-addr.arpa." for 192.0.2.1, the 32 reversed nibbles under
// "ip6.arpa." for an IPv6 address. An IPv4-mapped IPv6 address is unmapped
// first. An invalid address gives "".
func ReverseName(addr netip.Addr) string {
	addr = addr.Unmap().WithZone("")
	switch {
	case addr.Is4():
		a := addr.As4()
		return strconv.Itoa(int(a[3])) + "." + strconv.Itoa(int(a[2])) + "." +
			strconv.Itoa(int(a[1])) + "." + strconv.Itoa(int(a[0])) + v4Arpa
	case addr.Is6():
		a := addr.As16()
		var b strings.Builder
		b.Grow(64 + len(v6Arpa))
		for i := len(a) - 1; i >= 0; i-- {
			b.WriteByte(hexDigit(a[i] & 0xF))
			b.WriteByte('.')
			b.WriteByte(hexDigit(a[i] >> 4))
			b.WriteByte('.')
		}
		return strings.TrimSuffix(b.String(), ".") + v6Arpa
	}
	return ""
}

func hexDigit(n byte) byte { return "0123456789abcdef"[n] }

// ReverseAddr parses a full reverse-lookup name (four octet labels under
// in-addr.arpa, or 32 nibble labels under ip6.arpa) back into an address.
// Partial names, RFC 2317 classless labels and anything else give false.
func ReverseAddr(name string) (netip.Addr, bool) {
	if labels, ok := reverseLabels(name, v4Arpa); ok && len(labels) == 4 {
		var a [4]byte
		for i, l := range labels {
			v, ok := octet(l)
			if !ok {
				return netip.Addr{}, false
			}
			a[3-i] = v
		}
		return netip.AddrFrom4(a), true
	}
	if labels, ok := reverseLabels(name, v6Arpa); ok && len(labels) == 32 {
		var a [16]byte
		for i, l := range labels {
			v, ok := nibble(l)
			if !ok {
				return netip.Addr{}, false
			}
			// labels[0] is the lowest nibble of the last byte
			j := 31 - i
			a[j/2] |= v << (4 * uint(1-j%2))
		}
		return netip.AddrFrom16(a), true
	}
	return netip.Addr{}, false
}

// IsReverseZone reports whether apex lies under in-addr.arpa or ip6.arpa
// (case-insensitive; a trailing dot is optional).
func IsReverseZone(apex string) bool {
	a := strings.ToLower(Fqdn(apex))
	return len(a) > len(v4Arpa) && strings.HasSuffix(a, v4Arpa) ||
		len(a) > len(v6Arpa) && strings.HasSuffix(a, v6Arpa)
}

// ReversePrefix returns the address prefix a reverse zone apex covers:
// "3.2.1.in-addr.arpa." is 1.2.3.0/24 (one to four octet labels give /8 to
// /32), "8.b.d.0.1.0.0.2.ip6.arpa." is 2001:db8::/32 (one to 32 nibble
// labels give /4 to /128). RFC 2317 classless names such as
// "0/25.2.0.192.in-addr.arpa." and anything else give false.
func ReversePrefix(apex string) (netip.Prefix, bool) {
	if labels, ok := reverseLabels(apex, v4Arpa); ok && len(labels) >= 1 && len(labels) <= 4 {
		var a [4]byte
		for i, l := range labels {
			v, ok := octet(l)
			if !ok {
				return netip.Prefix{}, false
			}
			a[len(labels)-1-i] = v
		}
		return netip.PrefixFrom(netip.AddrFrom4(a), 8*len(labels)), true
	}
	if labels, ok := reverseLabels(apex, v6Arpa); ok && len(labels) >= 1 && len(labels) <= 32 {
		var a [16]byte
		for i, l := range labels {
			v, ok := nibble(l)
			if !ok {
				return netip.Prefix{}, false
			}
			j := len(labels) - 1 - i // nibble index from the top
			a[j/2] |= v << (4 * uint(1-j%2))
		}
		return netip.PrefixFrom(netip.AddrFrom16(a), 4*len(labels)), true
	}
	return netip.Prefix{}, false
}

// reverseLabels strips the arpa suffix (case-insensitive) from name and
// returns the remaining labels in written order. It reports false when the
// suffix is absent or nothing precedes it.
func reverseLabels(name, suffix string) ([]string, bool) {
	name = Fqdn(name)
	if len(name) <= len(suffix) || !strings.EqualFold(name[len(name)-len(suffix):], suffix) {
		return nil, false
	}
	return strings.Split(name[:len(name)-len(suffix)], "."), true
}

// octet parses a decimal label 0..255 with no sign or leading zeros.
func octet(s string) (byte, bool) {
	if !allDigits(s) || len(s) > 3 || (len(s) > 1 && s[0] == '0') {
		return 0, false
	}
	v, err := strconv.ParseUint(s, 10, 8)
	return byte(v), err == nil
}

// nibble parses a single hexadecimal digit label.
func nibble(s string) (byte, bool) {
	if len(s) != 1 {
		return 0, false
	}
	switch c := s[0]; {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}
