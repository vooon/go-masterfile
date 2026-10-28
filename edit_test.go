// SPDX-License-Identifier: Apache-2.0

package masterfile

import (
	"bytes"
	"cmp"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	acmeToken = "8NwtedqEdkceTHTZILXsMU2UWEeEon24tXw0dSSDkrs"
	fakeToken = "fake/XKo9kaBlVnj9q0XWAWdoSYEPCOrhiZk3ztoBHx5c3O6X"
)

var acmePlacement = Placement{{Owner: "_acme-challenge"}, {Prefix: "_acme-challenge."}}

func openFixture(t *testing.T, name string) *Zone {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "edit", name))
	require.NoError(t, err)
	z, err := Parse(data, "")
	require.NoError(t, err, "Parse(%s)", name)
	return z
}

// apply runs ops and fails the test on error.
func apply(t *testing.T, z *Zone, ops ...Op) []Result {
	t.Helper()
	rs, err := z.Apply(ops...)
	require.NoError(t, err, "Apply")
	return rs
}

func sel(owner string, types ...uint16) Selector { return Selector{Owner: owner, Types: types} }

func rr(rtype uint16, content string) RR { return RR{Type: rtype, Content: content} }

// editCase is one golden scenario: operations applied to a fixture, the
// committed bytes compared with testdata/edit/<golden>.golden.
type editCase struct {
	name    string
	fixture string
	golden  string // defaults to name
	changed bool   // expected Zone.Changed after apply
	multi   bool   // a multi-step flow: not idempotent as a whole
	want    []Result
	apply   func(t *testing.T, z *Zone) []Result
}

func editCases() []editCase {
	ptr := func(target string) RR { return rr(dns.TypePTR, target) }
	txt := func(value string) RR { return rr(dns.TypeTXT, value) }
	acme := func(owner string, records ...RR) Replace {
		return Replace{Selector: sel(owner, dns.TypeTXT), Records: records, Placement: acmePlacement}
	}
	phSel := Selector{Owner: "_acme-challenge", Types: []uint16{dns.TypeTXT}, Contents: []string{"placeholder"}}
	ph := func(token string) Replace {
		return Replace{Selector: phSel, Records: []RR{txt(token)}, Placement: acmePlacement}
	}
	one := func(op Op) func(t *testing.T, z *Zone) []Result {
		return func(t *testing.T, z *Zone) []Result { return apply(t, z, op) }
	}
	return []editCase{
		{name: "ptr-append", fixture: "rev.zone", changed: true,
			want: []Result{{Inserted: 1, Index: 13, Changed: true}},
			apply: one(Replace{Selector: Selector{Owner: "4", Types: []uint16{dns.TypePTR}, Contents: []string{"new.example.com."}},
				Records: []RR{ptr("new.example.com.")}, Placement: Placement{{Owner: "4"}}})},
		{name: "ptr-append-same", fixture: "rev.zone", changed: false,
			want: []Result{{Matched: 1, Removed: 1, Inserted: 1, Index: 11}},
			apply: one(Replace{Selector: Selector{Owner: "4", Types: []uint16{dns.TypePTR}, Contents: []string{"hub.example.com."}},
				Records: []RR{ptr("hub.example.com.")}, Placement: Placement{{Owner: "4"}}})},
		{name: "ptr-replace", fixture: "rev.zone", changed: true,
			want:  []Result{{Matched: 2, Removed: 1, Inserted: 1, Index: 11, Changed: true}},
			apply: one(Replace{Selector: sel("4.2.0.192.in-addr.arpa.", dns.TypePTR), Records: []RR{ptr("rebooted.example.com.")}, Mode: ReplaceFirst})},
		{name: "ptr-replace-all", fixture: "rev.zone", changed: true,
			want:  []Result{{Matched: 2, Removed: 2, Inserted: 1, Index: 11, Changed: true}},
			apply: one(Replace{Selector: sel("4", dns.TypePTR), Records: []RR{ptr("clean.example.com.")}})},
		{name: "ptr-create", fixture: "rev.zone", changed: true,
			want:  []Result{{Inserted: 1, Index: 13, Changed: true}},
			apply: one(Replace{Selector: sel("5", dns.TypePTR), Records: []RR{ptr("five.example.com.")}, Placement: Placement{{Owner: "5"}}})},
		{name: "ptr-delete-target", fixture: "rev.zone", changed: true,
			want:  []Result{{Matched: 1, Removed: 1, Index: -1, Changed: true}},
			apply: one(Delete{Selector{Owner: "4", Types: []uint16{dns.TypePTR}, Contents: []string{"legacy.example.com."}}})},
		{name: "ddns-new", fixture: "fwd.zone", changed: true,
			want:  []Result{{Inserted: 2, Index: 15, Changed: true}},
			apply: one(Replace{Selector: sel("new-entry", dns.TypeA, dns.TypeAAAA), Records: []RR{rr(dns.TypeA, "192.0.2.4"), rr(dns.TypeAAAA, "2001:db8::4")}})},
		{name: "ddns-loop-v4", fixture: "fwd.zone", changed: true,
			want:  []Result{{Matched: 1, Removed: 1, Inserted: 1, Index: 10, Changed: true}},
			apply: one(Replace{Selector: sel("loop", dns.TypeA), Records: []RR{rr(dns.TypeA, "192.0.2.10")}})},
		{name: "ddns-loop-v4v6", fixture: "fwd.zone", changed: true,
			want:  []Result{{Matched: 2, Removed: 2, Inserted: 2, Index: 10, Changed: true}},
			apply: one(Replace{Selector: sel("LOOP.at.example.com.", dns.TypeA, dns.TypeAAAA), Records: []RR{rr(dns.TypeA, "192.0.2.10"), rr(dns.TypeAAAA, "2001:db8::10")}})},
		{name: "acme-apex", fixture: "fwd.zone", changed: true,
			want:  []Result{{Inserted: 1, Index: 15, Changed: true}},
			apply: one(acme("_acme-challenge", txt(fakeToken)))},
		{name: "acme-apex-ttl60", fixture: "fwd.zone", golden: "acme-apex", changed: true,
			want:  []Result{{Inserted: 1, Index: 15, Changed: true}},
			apply: one(acme("_acme-challenge", RR{Type: dns.TypeTXT, TTL: 60, Content: fakeToken}))}, // TTL 60 equals $TTL
		{name: "acme-zot", fixture: "fwd.zone", changed: true,
			want:  []Result{{Matched: 1, Removed: 1, Inserted: 1, Index: 14, Changed: true}},
			apply: one(acme("_acme-challenge.zot", txt(fakeToken)))},
		{name: "acme-wildcard-present", fixture: "fwd-placeholder.zone", changed: true, multi: true,
			want: []Result{{Matched: 1, Removed: 1, Inserted: 1, Index: 15, Changed: true}, {Inserted: 1, Index: 16, Changed: true}},
			apply: func(t *testing.T, z *Zone) []Result {
				return apply(t, z, ph("fake/token1-helloworld"), ph("fake/token2-helloworld"))
			}},
		{name: "acme-wildcard-clean", fixture: "fwd-placeholder.zone", changed: true, multi: true,
			want: []Result{
				{Matched: 1, Removed: 1, Inserted: 1, Index: 15, Changed: true}, {Inserted: 1, Index: 16, Changed: true},
				{Matched: 2, Removed: 1, Inserted: 1, Index: 16, Changed: true}, {Matched: 2, Removed: 1, Index: -1, Changed: true},
			},
			apply: func(t *testing.T, z *Zone) []Result {
				return apply(t, z, ph("fake/token1-helloworld"), ph("fake/token2-helloworld"),
					Collapse{Owner: "_acme-challenge", Type: dns.TypeTXT, Drop: []string{"fake/token2-helloworld"}, Keep: "placeholder", Placement: acmePlacement},
					Collapse{Owner: "_acme-challenge", Type: dns.TypeTXT, Drop: []string{"fake/token1-helloworld"}, Keep: "placeholder", Placement: acmePlacement})
			}},
		{name: "acme-collapse-duplicates", fixture: "fwd-placeholder.zone", changed: true, multi: true,
			want: []Result{{Matched: 1, Inserted: 1, Index: 16, Changed: true}, {Matched: 3, Removed: 1, Index: -1, Changed: true}},
			apply: func(t *testing.T, z *Zone) []Result {
				rs := apply(t, z, AddRemove{Owner: "_acme-challenge", Type: dns.TypeTXT, Add: []string{"x"}})
				dup, _ := NewRecord("_acme-challenge", 0, dns.TypeTXT, "placeholder")
				z.Entries = slices.Insert(z.Entries, 16, dup.WithComments("dup")) // a second placeholder, by hand
				return append(rs, apply(t, z, Collapse{Owner: "_acme-challenge", Type: dns.TypeTXT, Drop: []string{"absent"}, Keep: "placeholder", Placement: acmePlacement})...)
			}},
		{name: "acme-collapse-no-txt", fixture: "fwd.zone", changed: true,
			want:  []Result{{Inserted: 1, Index: 15, Changed: true}},
			apply: one(Collapse{Owner: "_acme-challenge", Type: dns.TypeTXT, Drop: []string{"whatever"}, Keep: "placeholder", Placement: acmePlacement})},
		{name: "acme-clean-zot", fixture: "fwd.zone", changed: true,
			want:  []Result{{Matched: 1, Removed: 1, Inserted: 1, Index: 14, Changed: true}},
			apply: one(Collapse{Owner: "_acme-challenge.zot", Type: dns.TypeTXT, Drop: []string{acmeToken}, Keep: "placeholder", Placement: acmePlacement})},
		{name: "addremove-add", fixture: "fwd.zone", changed: true,
			want: []Result{{Matched: 1, Inserted: 1, Index: 11, Changed: true}, {Matched: 2, Index: -1}},
			apply: func(t *testing.T, z *Zone) []Result {
				op := AddRemove{Owner: "loop", Type: dns.TypeA, Add: []string{"192.0.2.4"}}
				return apply(t, z, op, op)
			}},
		{name: "addremove-remove", fixture: "fwd.zone", changed: true,
			want: []Result{{Matched: 1, Removed: 1, Index: -1, Changed: true}, {Index: -1}},
			apply: func(t *testing.T, z *Zone) []Result {
				op := AddRemove{Owner: "loop", Type: dns.TypeA, Remove: []string{"192.0.2.1"}}
				return apply(t, z, op, op)
			}},
		{name: "addremove-continuation", fixture: "fwd-placeholder.zone", changed: true, multi: true,
			want: []Result{{Matched: 1, Removed: 1, Inserted: 1, Index: 15, Changed: true}, {Inserted: 1, Index: 16, Changed: true}, {Matched: 2, Removed: 1, Index: -1, Changed: true}},
			apply: func(t *testing.T, z *Zone) []Result {
				return apply(t, z, ph("tok-1"), ph("tok-2"), AddRemove{Owner: "_acme-challenge", Type: dns.TypeTXT, Remove: []string{"tok-2"}})
			}},
		{name: "addremove-empty-set-placement", fixture: "fwd.zone", changed: true,
			want:  []Result{{Inserted: 1, Index: 15, Changed: true}},
			apply: one(AddRemove{Owner: "_acme-challenge", Type: dns.TypeTXT, Add: []string{"tok"}, Placement: acmePlacement})},
		{name: "delete-owner", fixture: "fwd.zone", changed: true,
			want:  []Result{{Matched: 2, Removed: 2, Index: -1, Changed: true}},
			apply: one(DeleteOwner{Owner: "loop"})},
		{name: "carried-comments", fixture: "rev.zone", changed: true, multi: true,
			want: []Result{{Matched: 2, Removed: 2, Inserted: 2, Index: 11, Changed: true}},
			apply: func(t *testing.T, z *Zone) []Result {
				// Comments of replaced records move to the first new record.
				z.Entries[11] = z.Entries[11].WithComments("hub box")
				z.Entries[12] = z.Entries[12].WithComments("old box")
				return apply(t, z, Replace{Selector: sel("4", dns.TypePTR), Records: []RR{ptr("a.example.com."), ptr("b.example.com.")}})
			}},
		// Insert with the default placement.
		{name: "insert-host", fixture: "fwd.zone", changed: true,
			want:  []Result{{Inserted: 2, Index: 12, Changed: true}}, // after loop's A/AAAA block, not between
			apply: one(Insert{Owner: "new-host", Records: []RR{rr(dns.TypeA, "192.0.2.9"), rr(dns.TypeAAAA, "2001:db8::9")}})},
		{name: "insert-acme", fixture: "fwd.zone", changed: true,
			want:  []Result{{Inserted: 1, Index: 15, Changed: true}}, // joins the _acme-challenge.* group
			apply: one(Insert{Owner: "_acme-challenge.foo", Records: []RR{txt("tok")}})},
		{name: "insert-sibling", fixture: "fwd.zone", changed: true,
			want:  []Result{{Inserted: 1, Index: 15, Changed: true}}, // next to the other name under zot
			apply: one(Insert{Owner: "b.zot", Records: []RR{rr(dns.TypeA, "192.0.2.5")}})},
		{name: "insert-apex", fixture: "fwd.zone", changed: true,
			want:  []Result{{Inserted: 1, Index: 8, Changed: true}}, // after the apex NS records
			apply: one(Insert{Owner: "@", Records: []RR{txt("v=spf1 -all")}})},
		{name: "insert-duplicate", fixture: "fwd.zone", changed: true,
			want: []Result{{Matched: 1, Inserted: 1, Index: 12, Changed: true}, {Matched: 2, Index: -1}},
			apply: func(t *testing.T, z *Zone) []Result {
				op := Insert{Owner: "loop", Records: []RR{rr(dns.TypeA, "192.0.2.1"), rr(dns.TypeA, "192.0.2.7")}}
				return apply(t, z, op, op)
			}},
		{name: "insert-nothing", fixture: "fwd.zone", changed: false,
			want:  []Result{{Index: -1}},
			apply: one(Insert{Owner: "loop"})},
	}
}

func TestEditGolden(t *testing.T) {
	withClock(t, 1763822926)
	for _, tc := range editCases() {
		t.Run(tc.name, func(t *testing.T) {
			z := openFixture(t, tc.fixture)
			loaded, before := z.Entries, slices.Clone(z.Entries)
			got := tc.apply(t, z)
			assert.Equal(t, tc.want, got, "results")
			require.Equal(t, tc.changed, z.Changed, "Changed")
			data, changed, err := z.Commit(true)
			require.NoError(t, err, "Commit")
			require.Equal(t, tc.changed, changed, "Commit changed")
			require.Equal(t, tc.changed, data != nil, "Commit = %v bytes", len(data))
			// Purity: the entries as loaded are untouched.
			assert.True(t, EntriesEqual(before, loaded), "loaded entries were modified in place")
			if !tc.changed {
				// A no-op case: the result is the fixture reformatted, unbumped.
				var buf bytes.Buffer
				require.NoError(t, z.Format(&buf, false))
				data = buf.Bytes()
			}
			golden := filepath.Join("testdata", "edit", cmp.Or(tc.golden, tc.name)+".golden")
			if *update && tc.golden == "" {
				if err := os.WriteFile(golden, data, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			wantData, err := os.ReadFile(golden)
			require.NoError(t, err)
			assert.Equal(t, string(wantData), string(data), "golden %s", golden)
			if tc.multi {
				return
			}
			// Idempotence: the same operation on the output changes nothing.
			again, err := Parse(data, "")
			require.NoError(t, err)
			tc.apply(t, again)
			var buf bytes.Buffer
			_ = again.Format(&buf, false)
			assert.False(t, again.Changed, "second application changed the zone:\n%s", buf.String())
		})
	}
}

func TestApplyErrors(t *testing.T) {
	fwd, err := os.ReadFile("testdata/edit/fwd.zone")
	require.NoError(t, err)
	_, err = Parse(fwd, "other.example.com.")
	assert.ErrorIs(t, err, ErrApexMismatch, "apex mismatch")
	z, err := Parse(fwd, "AT.example.com")
	require.NoError(t, err, "matching apex")
	require.Equal(t, "at.example.com.", z.Apex(), "matching apex")
	a := []RR{rr(dns.TypeA, "192.0.2.9")}
	for name, tc := range map[string]struct {
		op   Op
		want error
	}{
		"replace outside":  {Replace{Selector: sel("www.example.net."), Records: a}, ErrNotInZone},
		"replace empty":    {Replace{Selector: Selector{}, Records: a}, ErrNotInZone},
		"replace anchor":   {Replace{Selector: sel("x"), Records: a, Placement: Placement{{Owner: "www.example.net."}}}, ErrNotInZone},
		"replace under":    {Replace{Selector: sel("x"), Records: a, Placement: Placement{{Under: "example.net."}}}, ErrNotInZone},
		"delete":           {Delete{sel("example.net.")}, ErrNotInZone},
		"delete owner":     {DeleteOwner{"www.example.net."}, ErrNotInZone},
		"addremove":        {AddRemove{Owner: "www.example.net.", Type: dns.TypeA}, ErrNotInZone},
		"addremove place":  {AddRemove{Owner: "x", Type: dns.TypeA, Placement: Placement{{Owner: "example.net."}}}, ErrNotInZone},
		"collapse":         {Collapse{Owner: "www.example.net.", Type: dns.TypeTXT, Keep: "p"}, ErrNotInZone},
		"collapse place":   {Collapse{Owner: "x", Type: dns.TypeTXT, Keep: "p", Placement: Placement{{Owner: "example.net."}}}, ErrNotInZone},
		"insert outside":   {Insert{Owner: "example.net.", Records: a}, ErrNotInZone},
		"insert place":     {Insert{Owner: "x", Records: a, Placement: Placement{{Owner: "example.net."}}}, ErrNotInZone},
		"must exist":       {Replace{Selector: sel("nothere", dns.TypeA), Records: a, MustExist: true}, ErrNotFound},
		"bad type":         {Replace{Selector: sel("x"), Records: []RR{{Type: 0, Content: "x"}}}, ErrInvalidRecord},
		"bad insert":       {Insert{Owner: "x", Records: []RR{rr(dns.TypeA, "")}}, ErrInvalidRecord},
		"bad add":          {AddRemove{Owner: "x", Type: dns.TypeA, Add: []string{"a ; b"}}, ErrInvalidRecord},
		"bad keep":         {Collapse{Owner: "x", Type: dns.TypeA, Keep: "("}, ErrInvalidRecord},
		"second op fails":  {Insert{Owner: "x", Records: a}, nil},
		"atomic: all gone": {DeleteOwner{"loop"}, nil},
	} {
		ops := []Op{tc.op}
		if tc.want == nil {
			ops = append(ops, DeleteOwner{"www.example.net."})
			tc.want = ErrNotInZone
		}
		rs, err := z.Apply(ops...)
		assert.ErrorIs(t, err, tc.want, "%s", name)
		assert.Nil(t, rs, "%s: results", name)
	}
	assert.False(t, z.Changed, "failed Apply must leave the zone untouched")
	assert.Len(t, z.Entries, 15, "failed Apply must leave the zone untouched")
	// An absent delete is a no-op without error.
	rs, err := z.Apply(Delete{sel("nothere", dns.TypeA)})
	assert.NoError(t, err, "absent delete")
	assert.Equal(t, []Result{{Index: -1}}, rs, "absent delete")
	assert.False(t, z.Changed, "absent delete")
	// Commit refuses what the reference parser rejects.
	_, err = z.Apply(Replace{Selector: sel("bad", dns.TypeA), Records: []RR{rr(dns.TypeA, "not-an-address")}})
	require.NoError(t, err)
	_, _, err = z.Commit(false)
	assert.ErrorIs(t, err, ErrUnsafeWrite, "Commit of a bad record")
	// Commit with nothing changed, and an empty Apply.
	y := openFixture(t, "fwd.zone")
	rs, err = y.Apply()
	assert.NoError(t, err, "empty Apply")
	assert.Empty(t, rs, "empty Apply")
	data, changed, err := y.Commit(true)
	assert.NoError(t, err, "Commit unchanged")
	assert.False(t, changed, "Commit unchanged")
	assert.Nil(t, data, "Commit unchanged")
}

func TestQueries(t *testing.T) {
	z := openFixture(t, "fwd.zone")
	assert.NoError(t, z.Check(), "Check")
	loop := z.Select(sel("loop"))
	if assert.Len(t, loop, 2, "Select loop") {
		assert.Equal(t, "A", loop[0].Type(), "Select loop")
		assert.Equal(t, "AAAA", loop[1].Type(), "Select loop")
	}
	assert.Len(t, z.Select(sel("", dns.TypeNS)), 2, "Select NS")
	assert.Nil(t, z.Select(sel("www.example.net.")), "Select outside")
	assert.Equal(t, []string{"at.example.com."}, z.Owners(sel("", dns.TypeNS)), "Owners NS")
	assert.Equal(t, []string{"_acme-challenge.zot.at.example.com."}, z.Owners(Selector{Types: []uint16{dns.TypeTXT}, Contents: []string{acmeToken}}), "Owners TXT")
	assert.Equal(t, []string{"at.example.com."}, z.Owners(sel("@", dns.TypeNS)), "Owners @")
	serial, ok := z.Serial()
	assert.True(t, ok, "Serial")
	assert.Equal(t, uint32(1763822925), serial, "Serial")
	sets := z.RRSets()
	wantSets := []RRSet{
		{"at.example.com.", "SOA", 60, []string{"ns1.example.com. hostmaster.example.com. 1763822925 1H 600 1W 1D"}},
		{"at.example.com.", "NS", 60, []string{"ns1.example.com.", "ns2.example.com."}},
		{"loop.at.example.com.", "A", 60, []string{"192.0.2.1"}},
		{"loop.at.example.com.", "AAAA", 60, []string{"2001:db8::1"}},
		{"_acme-challenge.zot.at.example.com.", "TXT", 60, []string{acmeToken}},
	}
	assert.True(t, slices.EqualFunc(sets, wantSets, rrsetEqual), "RRSets = %+v", sets)
	assert.Equal(t, "loop.at.example.com.", z.AbsoluteOwner(z.Entries[10]), "AbsoluteOwner")
	assert.Empty(t, z.AbsoluteOwner(Entry{kind: Record}), "AbsoluteOwner of ownerless")
	// Ownerless records and unknown TTL in RRSets; non-numeric serial.
	y, err := Parse([]byte(`example.org. IN SOA ns host abc 2 3 4 5
 IN A 192.0.2.1
www 30 IN A 192.0.2.2
`), "")
	require.NoError(t, err)
	_, ok = y.Serial()
	assert.False(t, ok, "non-numeric serial")
	sets = y.RRSets()
	if assert.Len(t, sets, 3, "RRSets") {
		assert.Equal(t, uint32(0), sets[1].TTL, "RRSets = %+v", sets)
		assert.Equal(t, uint32(30), sets[2].TTL, "RRSets = %+v", sets)
	}
	_, ok = New("example.org.").Serial()
	assert.False(t, ok, "no SOA serial")
	// Hand-built entries with absolute owners are matched like relative ones.
	w := New("example.org.")
	abs, _ := NewRecord("www.example.org.", 0, dns.TypeA, "192.0.2.1")
	w.Entries = append(w.Entries, abs)
	assert.Len(t, w.Select(sel("www", dns.TypeA)), 1, "Select of an absolute owner")
	rs := apply(t, w, Insert{Owner: "www", Records: []RR{rr(dns.TypeA, "192.0.2.1")}})
	assert.False(t, rs[0].Changed, "Insert of a present absolute record = %+v", rs)
	assert.Equal(t, 1, rs[0].Matched, "Insert of a present absolute record = %+v", rs)
}

func rrsetEqual(a, b RRSet) bool {
	return a.Owner == b.Owner && a.Type == b.Type && a.TTL == b.TTL && slices.Equal(a.Contents, b.Contents)
}

// Spec (edit) 6.3.
func TestContentMatching(t *testing.T) {
	z, err := Parse([]byte(`$ORIGIN example.org.
@ IN SOA ns host 1 2 3 4 5
@ IN MX 10 mx.example.com.
t IN TXT "a b"
u IN TXT "a" "b"
c IN CAA 0 issue "ca.example"
p IN PTR host.example.com.
`), "")
	require.NoError(t, err)
	for _, tc := range []struct {
		owner   string
		rtype   uint16
		content string
		want    bool
	}{
		{"@", dns.TypeMX, "10   mx.example.com.", true},
		{"@", dns.TypeMX, "20 mx.example.com.", false},
		{"t", dns.TypeTXT, "a b", true},
		{"u", dns.TypeTXT, "ab", true},
		{"t", dns.TypeTXT, "a  b", false},
		{"c", dns.TypeCAA, `0 issue "ca.example"`, true},
		{"p", dns.TypePTR, "HOST.example.com.", false},
		{"P", dns.TypePTR, "host.example.com.", true},
	} {
		got := len(z.Select(Selector{Owner: tc.owner, Types: []uint16{tc.rtype}, Contents: []string{tc.content}})) == 1
		assert.Equal(t, tc.want, got, "%s %d %q: match", tc.owner, tc.rtype, tc.content)
	}
	for _, tc := range []struct {
		rtype    uint16
		in, want string
	}{
		{dns.TypeSPF, "a  b", "a  b"},
		{65280, " a  b ", "a b"},
		{dns.TypeCAA, `0 issue "ca.example; x"`, "0 issue ca.example; x"},
		{dns.TypeCAA, `0 issue "unterminated`, `0 issue "unterminated`},
		{dns.TypeMX, "10 mx ; comment", "10 mx ; comment"},
		{dns.TypeTXT, `"keeps quotes"`, `"keeps quotes"`},
	} {
		assert.Equal(t, tc.want, normalizeContent(tc.rtype, tc.in), "normalizeContent(%d, %q)", tc.rtype, tc.in)
	}
}

func TestPlacement(t *testing.T) {
	z := openFixture(t, "fwd.zone")
	n := len(z.Entries)
	for _, tc := range []struct {
		p    Placement
		want int
	}{
		{nil, n},
		{Placement{{Owner: "nothere"}}, n},
		{Placement{{Owner: "loop"}}, 12},
		{Placement{{Owner: "nothere"}, {Prefix: "_ACME-challenge."}}, 15},
		{Placement{{Prefix: "_acme-challenge."}, {Owner: "loop"}}, 15},
		{Placement{{}}, n},
		{Placement{{Owner: "@"}}, 8},
		{Placement{{Type: dns.TypeNS}}, 8},
		{Placement{{Type: dns.TypeA}}, 12}, // after loop's AAAA too
		{Placement{{Type: dns.TypeTXT}}, 15},
		{Placement{{Type: dns.TypeMX}}, n},
		{Placement{{Under: "zot"}}, 15},
		{Placement{{Under: "ZOT.at.example.com."}}, 15},
		{Placement{{Under: "@"}}, 15},
		{Placement{{Under: "loop", Type: dns.TypeAAAA}}, 12},
		{Placement{{Under: "loop", Type: dns.TypeTXT}}, n},
		{Placement{{Owner: "loop", Prefix: "x"}}, n},
	} {
		p, err := z.placement(tc.p)
		require.NoError(t, err)
		assert.Equal(t, tc.want, z.placementIndex(z.Entries, p), "placementIndex(%+v)", tc.p)
	}
	for _, tc := range []struct {
		owner string
		want  Placement
	}{
		{"@", Placement{{Owner: "@"}, {Type: dns.TypeA}}},
		{"www", Placement{{Owner: "www"}, {Under: "www"}, {Type: dns.TypeA}}},
		// Attribute leaves (RFC 8552) never fall back to the type anchor.
		{"_acme-challenge.zot.at.example.com.", Placement{{Owner: "_acme-challenge.zot"}, {Prefix: "_acme-challenge."}, {Under: "zot"}}},
		{"_acme-challenge", Placement{{Owner: "_acme-challenge"}, {Under: "_acme-challenge"}}},
		{"_dmarc", Placement{{Owner: "_dmarc"}, {Under: "_dmarc"}}},
		{"host._tcp", Placement{{Owner: "host._tcp"}, {Prefix: "host."}, {Under: "_tcp"}, {Type: dns.TypeA}}},
		{`a\.b.c`, Placement{{Owner: `a\.b.c`}, {Prefix: `a\.b.`}, {Under: "c"}, {Type: dns.TypeA}}},
		{"example.net.", Placement{{Type: dns.TypeA}}},
	} {
		assert.Equal(t, tc.want, z.DefaultPlacement(tc.owner, dns.TypeA), "DefaultPlacement(%q)", tc.owner)
	}
	assert.False(t, underRel(`a\.zot`, "zot"), "underRel")
	assert.True(t, underRel("a.zot", "zot"), "underRel")
	assert.False(t, underRel("azot", "zot"), "underRel")
}

func TestInsert_AttributeLeafGoesToEnd(t *testing.T) {
	// The zone has TXT records of its own; a first _acme-challenge must not
	// be filed after the last of them (the spec's "same type" fallback is
	// for hosts), but at the end, where a human adds an unrelated name.
	z, err := Parse([]byte(`$ORIGIN example.org.
@ IN SOA ns1 hostmaster 1 1h 10m 1w 1h
; mail
@ IN MX 10 mx
@ IN TXT "v=spf1 mx -all"
_dmarc IN TXT "v=DMARC1; p=reject"
; hosts
www IN A 192.0.2.1
mx IN A 192.0.2.25
`), "")
	require.NoError(t, err)

	_, err = z.Apply(Insert{Owner: "_acme-challenge", Records: []RR{{Type: dns.TypeTXT, Content: "tok"}}})
	require.NoError(t, err)
	last := z.Entries[len(z.Entries)-1]
	assert.Equal(t, "_acme-challenge", last.Owner(), "challenge record is last")

	// A challenge for a host files under that host (its parent), not with
	// the other TXTs and not at the end.
	res, err := z.Apply(Insert{Owner: "_acme-challenge.www", Records: []RR{{Type: dns.TypeTXT, Content: "tok2"}}})
	require.NoError(t, err)
	assert.Equal(t, "www", z.Entries[res[0].Index-1].Owner(), "right after its host")

	// A host still files with its kind.
	res, err = z.Apply(Insert{Owner: "ftp", Records: []RR{{Type: dns.TypeA, Content: "192.0.2.2"}}})
	require.NoError(t, err)
	assert.Equal(t, "mx", z.Entries[res[0].Index-1].Owner(), "after the last A record")
}

func TestEntryConstructors(t *testing.T) {
	z := New("example.org.")
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"$origin", []string{"sub"}, "$ORIGIN sub."},
		{"$TTL", []string{"1h"}, "$TTL 1h"},
		{"$INCLUDE", []string{`"a b.zone"`, "sub"}, `$INCLUDE "a b.zone" sub`},
		{"$GENERATE", []string{"1-10", "host-$", "A", "192.0.2.$"}, "$GENERATE 1-10 host-$ A 192.0.2.$"},
	} {
		e, err := NewDirective(tc.name, tc.args...)
		require.NoError(t, err, "NewDirective(%q)", tc.name)
		assert.Equal(t, tc.want, directiveText(e), "NewDirective(%q, %q)", tc.name, tc.args)
		z.Entries = append(z.Entries, e)
	}
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"$NOPE", []string{"x"}},
		{"$TTL", nil},
		{"$TTL", []string{"soon"}},
		{"$ORIGIN", []string{"a b"}},
		{"$ORIGIN", []string{"a\nb IN A 192.0.2.1"}},
		{"$ORIGIN", []string{"a ; comment"}},
		{"$ORIGIN", []string{"("}},
		{"$ORIGIN", []string{"\"open"}},
	} {
		_, err := NewDirective(tc.name, tc.args...)
		assert.ErrorIs(t, err, ErrInvalidEntry, "NewDirective(%q, %q)", tc.name, tc.args)
	}
	for in, want := range map[string]string{"note": "; note", ";; two": ";; two", "": ";", "trailing  ": "; trailing"} {
		e, err := NewComment(in)
		assert.NoError(t, err, "NewComment(%q)", in)
		assert.Equal(t, Comment, e.Kind(), "NewComment(%q)", in)
		assert.Equal(t, want, e.Comment(), "NewComment(%q)", in)
	}
	for _, in := range []string{"a\nb", "a\rb", "a\x00b"} {
		_, err := NewComment(in)
		assert.ErrorIs(t, err, ErrInvalidEntry, "NewComment(%q)", in)
	}
	// A file built from nothing commits and verifies.
	z = New("example.org.")
	z.Entries = append(z.Entries,
		must(NewDirective("$ORIGIN", "example.org.")),
		must(NewDirective("$TTL", "1h")),
		must(NewComment("built by hand")),
		must(NewRecord("@", 0, dns.TypeSOA, "ns1 hostmaster 2024010100 1h 10m 1w 1h")),
		must(NewRecord("@", 0, dns.TypeNS, "ns1")),
	)
	_, changed, err := z.Commit(false)
	require.NoError(t, err, "Commit of an unflagged new zone")
	require.False(t, changed, "Commit of an unflagged new zone")
	z.Changed = true
	data, changed, err := z.Commit(false)
	require.NoError(t, err, "Commit")
	require.True(t, changed, "Commit")
	want := `$ORIGIN example.org.
$TTL 1h
; built by hand
@ IN SOA ns1 hostmaster (
    2024010100 ; serial  Mon, 01 Jan 2024 #00
    1h         ; refresh
    10m        ; retry
    1w         ; expire
    1h         ; minimum
)
  IN NS  ns1
`
	assert.Equal(t, want, string(data))
	assert.NoError(t, z.Check(), "Check")
}

func must(e Entry, err error) Entry {
	if err != nil {
		panic(err)
	}
	return e
}

// Properties over generated zones (edit spec section 7).
func TestEditProperties(t *testing.T) {
	r := newRand(7, 8)
	for i := range 200 {
		text := `$ORIGIN example.org.
@ IN SOA ns host 1 2 3 4 5
` + genZone(r)
		z, err := Parse([]byte(text), "")
		if err != nil {
			continue // genZone may produce a second SOA under another origin
		}
		before := z.RRSets()
		comments := allComments(z.Entries)
		if len(before) < 2 {
			continue
		}
		set := before[1+r.IntN(len(before)-1)]
		if !InZone(set.Owner, z.apex) {
			continue
		}
		rtype := typeNames[set.Type]
		s := sel(set.Owner, rtype)

		// Replace then Delete removes exactly that set.
		_, err = z.Apply(Replace{Selector: s, Records: []RR{rr(dns.TypeTXT, "x")}},
			Delete{Selector{Owner: set.Owner, Types: []uint16{dns.TypeTXT}, Contents: []string{"x"}}})
		require.NoError(t, err, "#%d Replace+Delete\n%s", i, text)
		wantSets := slices.DeleteFunc(slices.Clone(before), func(s RRSet) bool { return s.Owner == set.Owner && s.Type == set.Type })
		require.True(t, slices.EqualFunc(z.RRSets(), wantSets, rrsetEqual), "#%d Replace+Delete: got %+v, want %+v\n%s", i, z.RRSets(), wantSets, text)

		// AddRemove add then remove restores the sets; so does Insert then Delete.
		y, _ := Parse([]byte(text), "")
		_, err = y.Apply(AddRemove{Owner: set.Owner, Type: dns.TypeA, Add: []string{"192.0.2.77"}},
			AddRemove{Owner: set.Owner, Type: dns.TypeA, Remove: []string{"192.0.2.77"}},
			Insert{Owner: set.Owner, Records: []RR{rr(dns.TypeA, "192.0.2.78")}},
			Delete{Selector{Owner: set.Owner, Types: []uint16{dns.TypeA}, Contents: []string{"192.0.2.78"}}})
		require.NoError(t, err, "#%d AddRemove/Insert\n%s", i, text)
		require.True(t, slices.EqualFunc(y.RRSets(), before, rrsetEqual), "#%d AddRemove/Insert round trip changed the RRsets\n%s", i, text)

		// Carried comments: a replace with insertion keeps every comment.
		x, _ := Parse([]byte(text), "")
		_, err = x.Apply(Replace{Selector: s, Records: []RR{rr(dns.TypeTXT, "x")}})
		require.NoError(t, err, "#%d Replace\n%s", i, text)
		after := allComments(x.Entries)
		for _, c := range comments {
			// Carried comments are joined onto one line, so look inside.
			require.True(t, slices.ContainsFunc(after, func(a string) bool { return strings.Contains(a, c) }), "#%d comment %q lost by Replace\n%s", i, c, text)
		}
		// And the result commits safely.
		_, _, err = x.Commit(true)
		require.NoError(t, err, "#%d Commit\n%s", i, text)
	}
}

func allComments(es []Entry) []string {
	var out []string
	for _, e := range es {
		out = append(out, e.Comments()...)
	}
	return out
}

func FuzzEdit(f *testing.F) {
	fwd, _ := os.ReadFile("testdata/edit/fwd.zone")
	f.Add(fwd, "loop", "192.0.2.9", uint16(dns.TypeA))
	f.Add(fwd, "_acme-challenge", "tok", uint16(dns.TypeTXT))
	f.Add([]byte(`@ IN SOA ns host 1 2 3 4 5
`), "@", "x", uint16(dns.TypeMX))
	f.Fuzz(func(t *testing.T, data []byte, owner, content string, rtype uint16) {
		z, err := Parse(data, "")
		if err != nil {
			return
		}
		record := []RR{{Type: rtype, Content: content}}
		s := Selector{Owner: owner, Types: []uint16{rtype}, Contents: []string{content}}
		p := Placement{{Owner: owner}, {Prefix: content}, {Under: owner}, {Type: rtype}}
		_, _ = z.Apply(Replace{Selector: s, Records: record, Placement: p})
		_, _ = z.Apply(Replace{Selector: Selector{Owner: owner}, Records: record, Mode: ReplaceFirst, MustExist: true})
		_, _ = z.Apply(Insert{Owner: owner, Records: record})
		_, _ = z.Apply(AddRemove{Owner: owner, Type: rtype, Add: []string{content}, Remove: []string{content}, Placement: p})
		_, _ = z.Apply(Collapse{Owner: owner, Type: rtype, Drop: []string{content}, Keep: content, Placement: p})
		_, _ = z.Apply(Delete{s}, DeleteOwner{owner})
		_ = z.Select(Selector{})
		_ = z.Owners(s)
		_ = z.RRSets()
		_, _ = z.Serial()
		_ = z.Check()
		if _, _, err := z.Commit(true); err != nil && !errors.Is(err, ErrUnsafeWrite) && !strings.Contains(err.Error(), "SOA has") {
			require.NoError(t, err, "Commit")
		}
	})
}
