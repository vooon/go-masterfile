// SPDX-License-Identifier: Apache-2.0

package masterfile

import (
	"math/rand/v2"
	"net/netip"
	"slices"
	"testing"
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
		if got := ReverseName(netip.MustParseAddr(tc.addr)); got != tc.want {
			t.Errorf("ReverseName(%s) = %q, want %q", tc.addr, got, tc.want)
		}
	}
	if got := ReverseName(netip.Addr{}); got != "" {
		t.Errorf("ReverseName(zero) = %q", got)
	}
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
		if ok != tc.ok || (ok && got.String() != tc.want) {
			t.Errorf("ReverseAddr(%q) = %v, %v; want %q, %v", tc.name, got, ok, tc.want, tc.ok)
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
		if !ok || got != a {
			t.Fatalf("ReverseAddr(ReverseName(%s)) = %s, %v", a, got, ok)
		}
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
		if got := IsReverseZone(tc.apex); got != tc.want {
			t.Errorf("IsReverseZone(%q) = %v, want %v", tc.apex, got, tc.want)
		}
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
		if ok != tc.ok || (ok && got.String() != tc.want) {
			t.Errorf("ReversePrefix(%q) = %v, %v; want %q, %v", tc.apex, got, ok, tc.want, tc.ok)
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
		if got := InZone(tc.name, tc.apex); got != tc.want {
			t.Errorf("InZone(%q, %q) = %v, want %v", tc.name, tc.apex, got, tc.want)
		}
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
		if ok != tc.ok || got != tc.want {
			t.Errorf("LongestZone(%q) = %q, %v; want %q, %v", tc.name, got, ok, tc.want, tc.ok)
		}
	}
	if _, ok := LongestZone("x.", nil); ok {
		t.Error("no apexes")
	}
	if got, _ := LongestZone("a.b.c.", []string{".", "c.", "b.c."}); got != "b.c." {
		t.Errorf("root among apexes: %q", got)
	}
	// Label counting is escape-aware.
	if labelCount(`a\.b.c.`) != 2 || labelCount(".") != 0 || labelCount("a") != 1 {
		t.Error("labelCount")
	}
	if got := slices.Collect(labels("a.b.")); !slices.Equal(got, []string{"a", "b", ""}) {
		t.Errorf("labels = %q", got)
	}
}
