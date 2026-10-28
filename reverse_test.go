// SPDX-License-Identifier: Apache-2.0

package masterfile

import (
	"math/rand/v2"
	"net/netip"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Spec (edit) 6.4.
func TestReverseName(t *testing.T) {
	for _, tc := range []struct{ addr, want string }{
		{"192.0.2.1", "1.2.0.192.in-addr.arpa."},
		{"2001:db8::1", "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa."},
		{"::ffff:192.0.2.1", "1.2.0.192.in-addr.arpa."},
		{"fe80::1%eth0", "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa."},
		{"0.0.0.0", "0.0.0.0.in-addr.arpa."},
		{"255.255.255.255", "255.255.255.255.in-addr.arpa."},
	} {
		assert.Equal(t, tc.want, ReverseName(netip.MustParseAddr(tc.addr)), "ReverseName(%s)", tc.addr)
	}
	assert.Empty(t, ReverseName(netip.Addr{}), "ReverseName(zero)")
}

func TestReverseAddr(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		ok         bool
	}{
		{"1.2.0.192.in-addr.arpa.", "192.0.2.1", true},
		{"1.2.0.192.IN-ADDR.ARPA", "192.0.2.1", true},
		{"2.0.192.in-addr.arpa.", "", false},
		{"1.2.0.192.1.in-addr.arpa.", "", false},
		{"1.2.0.256.in-addr.arpa.", "", false},
		{"1.2.0.01.in-addr.arpa.", "", false},
		{"1.2.0.-1.in-addr.arpa.", "", false},
		{"0/25.2.0.192.in-addr.arpa.", "", false},
		{"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.", "2001:db8::1", true},
		{"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.B.D.0.1.0.0.2.IP6.ARPA.", "2001:db8::1", true},
		{"8.b.d.0.1.0.0.2.ip6.arpa.", "", false},
		{"g.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.", "", false},
		{"10.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.", "", false},
		{"in-addr.arpa.", "", false},
		{"www.example.org.", "", false},
		{"", "", false},
	} {
		got, ok := ReverseAddr(tc.name)
		assert.Equal(t, tc.ok, ok, "ReverseAddr(%q) = %v, %v", tc.name, got, ok)
		if tc.ok && ok {
			assert.Equal(t, tc.want, got.String(), "ReverseAddr(%q)", tc.name)
		}
	}
}

func TestReverseRoundTrip(t *testing.T) {
	r := rand.New(rand.NewPCG(5, 6))
	for range 2000 {
		var a netip.Addr
		if r.IntN(2) == 0 {
			var b [4]byte
			for i := range b {
				b[i] = byte(r.UintN(256))
			}
			a = netip.AddrFrom4(b)
		} else {
			var b [16]byte
			for i := range b {
				b[i] = byte(r.UintN(256))
			}
			a = netip.AddrFrom16(b)
		}
		got, ok := ReverseAddr(ReverseName(a))
		require.True(t, ok, "ReverseAddr(ReverseName(%s)) = %s, %v", a, got, ok)
		require.Equal(t, a, got, "ReverseAddr(ReverseName(%s))", a)
	}
}

func TestIsReverseZone(t *testing.T) {
	for _, tc := range []struct {
		apex string
		want bool
	}{
		{"3.2.1.IN-ADDR.ARPA", true},
		{"3.2.1.in-addr.arpa.", true},
		{"8.b.d.0.1.0.0.2.ip6.arpa.", true},
		{"in-addr.arpa.", false},
		{"ip6.arpa", false},
		{"example.org.", false},
		{"in-addr.arpa.example.org.", false},
		{"", false},
	} {
		assert.Equal(t, tc.want, IsReverseZone(tc.apex), "IsReverseZone(%q)", tc.apex)
	}
}

func TestReversePrefix(t *testing.T) {
	for _, tc := range []struct {
		apex, want string
		ok         bool
	}{
		{"3.2.1.in-addr.arpa.", "1.2.3.0/24", true},
		{"1.in-addr.arpa.", "1.0.0.0/8", true},
		{"2.1.in-addr.arpa", "1.2.0.0/16", true},
		{"4.3.2.1.in-addr.arpa.", "1.2.3.4/32", true},
		{"5.4.3.2.1.in-addr.arpa.", "", false},
		{"0/25.2.0.192.in-addr.arpa.", "", false},
		{"256.in-addr.arpa.", "", false},
		{"8.b.d.0.1.0.0.2.ip6.arpa.", "2001:db8::/32", true},
		{"2.ip6.arpa.", "2000::/4", true},
		{"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.", "2001:db8::1/128", true},
		{"1.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.", "", false},
		{"x.ip6.arpa.", "", false},
		{"in-addr.arpa.", "", false},
		{"example.org.", "", false},
	} {
		got, ok := ReversePrefix(tc.apex)
		assert.Equal(t, tc.ok, ok, "ReversePrefix(%q) = %v, %v", tc.apex, got, ok)
		if tc.ok && ok {
			assert.Equal(t, tc.want, got.String(), "ReversePrefix(%q)", tc.apex)
		}
	}
}

func TestInZone(t *testing.T) {
	for _, tc := range []struct {
		name, apex string
		want       bool
	}{
		{"www.example.org.", "example.org.", true},
		{"example.org.", "example.org.", true},
		{"WWW.Example.ORG", "example.org", true},
		{"myexample.org.", "example.org.", false},
		{"example.net.", "example.org.", false},
		{"org.", "example.org.", false},
		{`a\.example.org.`, "example.org.", false},
		{"anything.", ".", true},
		{".", ".", true},
	} {
		assert.Equal(t, tc.want, InZone(tc.name, tc.apex), "InZone(%q, %q)", tc.name, tc.apex)
	}
}

func TestLongestZone(t *testing.T) {
	apexes := []string{"example.org.", "b.example.org.", "other.org."}
	for _, tc := range []struct {
		name, want string
		ok         bool
	}{
		{"a.b.example.org.", "b.example.org.", true},
		{"www.example.org.", "example.org.", true},
		{"b.example.org.", "b.example.org.", true},
		{"example.net.", "", false},
		{"other.org.", "other.org.", true},
	} {
		got, ok := LongestZone(tc.name, apexes)
		assert.Equal(t, tc.ok, ok, "LongestZone(%q) ok", tc.name)
		assert.Equal(t, tc.want, got, "LongestZone(%q)", tc.name)
	}
	_, ok := LongestZone("x.", nil)
	assert.False(t, ok, "no apexes")
	got, _ := LongestZone("a.b.c.", []string{".", "c.", "b.c."})
	assert.Equal(t, "b.c.", got, "root among apexes")
	// Label counting is escape-aware.
	assert.Equal(t, 2, labelCount(`a\.b.c.`), "labelCount")
	assert.Equal(t, 0, labelCount("."), "labelCount")
	assert.Equal(t, 1, labelCount("a"), "labelCount")
	assert.Equal(t, []string{"a", "b", ""}, slices.Collect(labels("a.b.")), "labels")
}
