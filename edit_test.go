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
)

const (
	acmeToken = "8NwtedqEdkceTHTZILXsMU2UWEeEon24tXw0dSSDkrs"
	fakeToken = "fake/XKo9kaBlVnj9q0XWAWdoSYEPCOrhiZk3ztoBHx5c3O6X"
	acmePlace = "_acme-challenge."
)

func rec(t *testing.T, owner string, ttl uint32, rtype uint16, rdata string) Entry {
	t.Helper()
	e, err := NewRecord(owner, ttl, rtype, rdata)
	if err != nil {
		t.Fatalf("NewRecord(%q, %d, %d, %q): %v", owner, ttl, rtype, rdata, err)
	}
	return e
}

func openFixture(t *testing.T, name string) *Zone {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "edit", name))
	if err != nil {
		t.Fatal(err)
	}
	z, err := Open(data, "")
	if err != nil {
		t.Fatalf("Open(%s): %v", name, err)
	}
	return z
}

var acmePlacement = Placement{{Owner: "_acme-challenge"}, {Prefix: acmePlace}}

// editCase is one golden scenario: operations applied to a fixture, the
// committed bytes compared with testdata/edit/<golden>.golden.
type editCase struct {
	name    string
	fixture string
	golden  string // defaults to name
	changed bool   // expected Changed() after apply
	multi   bool   // a multi-step flow: not idempotent as a whole
	want    []Result
	apply   func(t *testing.T, z *Zone) []Result
}

// op collects an operation's result, failing the test on error.
type op struct {
	t   *testing.T
	got []Result
}

func (o *op) do(r Result, err error) {
	o.t.Helper()
	if err != nil {
		o.t.Fatalf("operation: %v", err)
	}
	o.got = append(o.got, r)
}

func editCases() []editCase {
	ptr := func(t *testing.T, target string) Entry { return rec(t, "4", 0, dns.TypePTR, target) }
	txt := func(t *testing.T, owner, value string) Entry { return rec(t, owner, 0, dns.TypeTXT, value) }
	all := ReplaceOptions{Mode: ReplaceAll}
	acme := ReplaceOptions{Mode: ReplaceAll, Placement: acmePlacement}
	phSel := Selector{Owner: "_acme-challenge", Types: []uint16{dns.TypeTXT}, Contents: []string{"placeholder"}}
	return []editCase{
		{name: "ptr-append", fixture: "rev.zone", changed: true,
			want: []Result{{Inserted: 1, Index: 13}},
			apply: func(t *testing.T, z *Zone) []Result {
				o := &op{t: t}
				o.do(z.Replace(Selector{Owner: "4", Types: []uint16{dns.TypePTR}, Contents: []string{"new.example.com."}},
					[]Entry{ptr(t, "new.example.com.")}, ReplaceOptions{Mode: ReplaceAll, Placement: Placement{{Owner: "4"}}}))
				return o.got
			}},
		{name: "ptr-append-same", fixture: "rev.zone", changed: false,
			want: []Result{{Matched: 1, Removed: 1, Inserted: 1, Index: 11}},
			apply: func(t *testing.T, z *Zone) []Result {
				o := &op{t: t}
				o.do(z.Replace(Selector{Owner: "4", Types: []uint16{dns.TypePTR}, Contents: []string{"hub.example.com."}},
					[]Entry{ptr(t, "hub.example.com.")}, ReplaceOptions{Mode: ReplaceAll, Placement: Placement{{Owner: "4"}}}))
				return o.got
			}},
		{name: "ptr-replace", fixture: "rev.zone", changed: true,
			want: []Result{{Matched: 2, Removed: 1, Inserted: 1, Index: 11}},
			apply: func(t *testing.T, z *Zone) []Result {
				o := &op{t: t}
				o.do(z.Replace(Selector{Owner: "4.2.0.192.in-addr.arpa.", Types: []uint16{dns.TypePTR}},
					[]Entry{ptr(t, "rebooted.example.com.")}, ReplaceOptions{Mode: ReplaceFirst}))
				return o.got
			}},
		{name: "ptr-replace-all", fixture: "rev.zone", changed: true,
			want: []Result{{Matched: 2, Removed: 2, Inserted: 1, Index: 11}},
			apply: func(t *testing.T, z *Zone) []Result {
				o := &op{t: t}
				o.do(z.Replace(Selector{Owner: "4", Types: []uint16{dns.TypePTR}}, []Entry{ptr(t, "clean.example.com.")}, all))
				return o.got
			}},
		{name: "ptr-create", fixture: "rev.zone", changed: true,
			want: []Result{{Inserted: 1, Index: 13}},
			apply: func(t *testing.T, z *Zone) []Result {
				o := &op{t: t}
				o.do(z.Replace(Selector{Owner: "5", Types: []uint16{dns.TypePTR}},
					[]Entry{rec(t, "5", 0, dns.TypePTR, "five.example.com.")}, ReplaceOptions{Mode: ReplaceAll, Placement: Placement{{Owner: "5"}}}))
				return o.got
			}},
		{name: "ptr-delete-target", fixture: "rev.zone", changed: true,
			want: []Result{{Matched: 1, Removed: 1, Index: -1}},
			apply: func(t *testing.T, z *Zone) []Result {
				o := &op{t: t}
				o.do(z.Delete(Selector{Owner: "4", Types: []uint16{dns.TypePTR}, Contents: []string{"legacy.example.com."}}))
				return o.got
			}},
		{name: "ddns-new", fixture: "fwd.zone", changed: true,
			want: []Result{{Inserted: 2, Index: 15}},
			apply: func(t *testing.T, z *Zone) []Result {
				o := &op{t: t}
				o.do(z.Replace(Selector{Owner: "new-entry", Types: []uint16{dns.TypeA, dns.TypeAAAA}},
					[]Entry{rec(t, "new-entry", 0, dns.TypeA, "192.0.2.4"), rec(t, "new-entry", 0, dns.TypeAAAA, "2001:db8::4")}, all))
				return o.got
			}},
		{name: "ddns-loop-v4", fixture: "fwd.zone", changed: true,
			want: []Result{{Matched: 1, Removed: 1, Inserted: 1, Index: 10}},
			apply: func(t *testing.T, z *Zone) []Result {
				o := &op{t: t}
				o.do(z.Replace(Selector{Owner: "loop", Types: []uint16{dns.TypeA}}, []Entry{rec(t, "loop", 0, dns.TypeA, "192.0.2.10")}, all))
				return o.got
			}},
		{name: "ddns-loop-v4v6", fixture: "fwd.zone", changed: true,
			want: []Result{{Matched: 2, Removed: 2, Inserted: 2, Index: 10}},
			apply: func(t *testing.T, z *Zone) []Result {
				o := &op{t: t}
				o.do(z.Replace(Selector{Owner: "LOOP.at.example.com.", Types: []uint16{dns.TypeA, dns.TypeAAAA}},
					[]Entry{rec(t, "loop", 0, dns.TypeA, "192.0.2.10"), rec(t, "loop", 0, dns.TypeAAAA, "2001:db8::10")}, all))
				return o.got
			}},
		{name: "acme-apex", fixture: "fwd.zone", changed: true,
			want: []Result{{Inserted: 1, Index: 15}},
			apply: func(t *testing.T, z *Zone) []Result {
				o := &op{t: t}
				o.do(z.Replace(Selector{Owner: "_acme-challenge", Types: []uint16{dns.TypeTXT}}, []Entry{txt(t, "_acme-challenge", fakeToken)}, acme))
				return o.got
			}},
		{name: "acme-apex-ttl60", fixture: "fwd.zone", golden: "acme-apex", changed: true,
			want: []Result{{Inserted: 1, Index: 15}},
			apply: func(t *testing.T, z *Zone) []Result {
				// TTL 60 equals $TTL, so the file is identical to acme-apex.
				o := &op{t: t}
				o.do(z.Replace(Selector{Owner: "_acme-challenge", Types: []uint16{dns.TypeTXT}}, []Entry{rec(t, "_acme-challenge", 60, dns.TypeTXT, fakeToken)}, acme))
				return o.got
			}},
		{name: "acme-zot", fixture: "fwd.zone", changed: true,
			want: []Result{{Matched: 1, Removed: 1, Inserted: 1, Index: 14}},
			apply: func(t *testing.T, z *Zone) []Result {
				o := &op{t: t}
				o.do(z.Replace(Selector{Owner: "_acme-challenge.zot", Types: []uint16{dns.TypeTXT}}, []Entry{txt(t, "_acme-challenge.zot", fakeToken)}, acme))
				return o.got
			}},
		{name: "acme-wildcard-present", fixture: "fwd-placeholder.zone", changed: true, multi: true,
			want: []Result{{Matched: 1, Removed: 1, Inserted: 1, Index: 15}, {Inserted: 1, Index: 16}},
			apply: func(t *testing.T, z *Zone) []Result {
				o := &op{t: t}
				o.do(z.Replace(phSel, []Entry{txt(t, "_acme-challenge", "fake/token1-helloworld")}, acme))
				o.do(z.Replace(phSel, []Entry{txt(t, "_acme-challenge", "fake/token2-helloworld")}, acme))
				return o.got
			}},
		{name: "acme-wildcard-clean", fixture: "fwd-placeholder.zone", changed: false,
			want: []Result{
				{Matched: 1, Removed: 1, Inserted: 1, Index: 15}, {Inserted: 1, Index: 16},
				{Matched: 2, Removed: 1, Inserted: 1, Index: 16}, {Matched: 2, Removed: 1, Index: -1},
			},
			apply: func(t *testing.T, z *Zone) []Result {
				o := &op{t: t}
				o.do(z.Replace(phSel, []Entry{txt(t, "_acme-challenge", "fake/token1-helloworld")}, acme))
				o.do(z.Replace(phSel, []Entry{txt(t, "_acme-challenge", "fake/token2-helloworld")}, acme))
				ph := txt(t, "_acme-challenge", "placeholder")
				o.do(z.Collapse("_acme-challenge", dns.TypeTXT, []string{"fake/token2-helloworld"}, ph, acmePlacement))
				o.do(z.Collapse("_acme-challenge", dns.TypeTXT, []string{"fake/token1-helloworld"}, ph, acmePlacement))
				return o.got
			}},
		{name: "acme-collapse-duplicates", fixture: "fwd-placeholder.zone", changed: true, multi: true,
			want: []Result{{Matched: 1, Inserted: 1, Index: 16}, {Matched: 3, Removed: 1, Index: -1}},
			apply: func(t *testing.T, z *Zone) []Result {
				o := &op{t: t}
				ph := txt(t, "_acme-challenge", "placeholder")
				o.do(z.AddRemove("_acme-challenge", dns.TypeTXT, []Entry{txt(t, "_acme-challenge", "x")}, nil, nil))
				z.entries = slices.Insert(z.entries, 16, ph.WithComments("dup")) // a second placeholder, by hand
				o.do(z.Collapse("_acme-challenge", dns.TypeTXT, []string{"absent"}, ph, acmePlacement))
				return o.got
			}},
		{name: "acme-collapse-no-txt", fixture: "fwd.zone", changed: true,
			want: []Result{{Inserted: 1, Index: 15}},
			apply: func(t *testing.T, z *Zone) []Result {
				o := &op{t: t}
				o.do(z.Collapse("_acme-challenge", dns.TypeTXT, []string{"whatever"}, txt(t, "_acme-challenge", "placeholder"), acmePlacement))
				return o.got
			}},
		{name: "acme-clean-zot", fixture: "fwd.zone", changed: true,
			want: []Result{{Matched: 1, Removed: 1, Inserted: 1, Index: 14}},
			apply: func(t *testing.T, z *Zone) []Result {
				o := &op{t: t}
				o.do(z.Collapse("_acme-challenge.zot", dns.TypeTXT, []string{acmeToken}, txt(t, "_acme-challenge.zot", "placeholder"), acmePlacement))
				return o.got
			}},
		{name: "addremove-add", fixture: "fwd.zone", changed: true,
			want: []Result{{Matched: 1, Inserted: 1, Index: 11}, {Matched: 2, Index: -1}},
			apply: func(t *testing.T, z *Zone) []Result {
				o := &op{t: t}
				o.do(z.AddRemove("loop", dns.TypeA, []Entry{rec(t, "loop", 0, dns.TypeA, "192.0.2.4")}, nil, nil))
				o.do(z.AddRemove("loop", dns.TypeA, []Entry{rec(t, "loop", 0, dns.TypeA, "192.0.2.4")}, nil, nil))
				return o.got
			}},
		{name: "addremove-remove", fixture: "fwd.zone", changed: true,
			want: []Result{{Matched: 1, Removed: 1, Index: -1}, {Index: -1}},
			apply: func(t *testing.T, z *Zone) []Result {
				o := &op{t: t}
				o.do(z.AddRemove("loop", dns.TypeA, nil, []string{"192.0.2.1"}, nil))
				o.do(z.AddRemove("loop", dns.TypeA, nil, []string{"192.0.2.1"}, nil))
				return o.got
			}},
		{name: "addremove-continuation", fixture: "fwd-placeholder.zone", changed: true, multi: true,
			want: []Result{{Matched: 1, Removed: 1, Inserted: 1, Index: 15}, {Inserted: 1, Index: 16}, {Matched: 2, Removed: 1, Index: -1}},
			apply: func(t *testing.T, z *Zone) []Result {
				o := &op{t: t}
				o.do(z.Replace(phSel, []Entry{txt(t, "_acme-challenge", "tok-1")}, acme))
				o.do(z.Replace(phSel, []Entry{txt(t, "_acme-challenge", "tok-2")}, acme))
				o.do(z.AddRemove("_acme-challenge", dns.TypeTXT, nil, []string{"tok-2"}, nil))
				return o.got
			}},
		{name: "addremove-empty-set-placement", fixture: "fwd.zone", changed: true,
			want: []Result{{Inserted: 1, Index: 15}},
			apply: func(t *testing.T, z *Zone) []Result {
				o := &op{t: t}
				o.do(z.AddRemove("_acme-challenge", dns.TypeTXT, []Entry{txt(t, "_acme-challenge", "tok")}, nil, acmePlacement))
				return o.got
			}},
		{name: "delete-owner", fixture: "fwd.zone", changed: true,
			want: []Result{{Matched: 2, Removed: 2, Index: -1}},
			apply: func(t *testing.T, z *Zone) []Result {
				o := &op{t: t}
				o.do(z.DeleteOwner("loop"))
				return o.got
			}},
		{name: "carried-comments", fixture: "rev.zone", changed: true, multi: true,
			want: []Result{{Matched: 2, Removed: 2, Inserted: 2, Index: 11}},
			apply: func(t *testing.T, z *Zone) []Result {
				// Comments of replaced records move to the first new record.
				z.entries[11] = z.entries[11].WithComments("hub box")
				z.entries[12] = z.entries[12].WithComments("old box")
				o := &op{t: t}
				o.do(z.Replace(Selector{Owner: "4", Types: []uint16{dns.TypePTR}},
					[]Entry{ptr(t, "a.example.com."), ptr(t, "b.example.com.")}, all))
				return o.got
			}},
	}
}

func TestEditGolden(t *testing.T) {
	withClock(t, 1763822926)
	for _, tc := range editCases() {
		t.Run(tc.name, func(t *testing.T) {
			z := openFixture(t, tc.fixture)
			before := slices.Clone(z.entries)
			got := tc.apply(t, z)
			if !slices.Equal(got, tc.want) {
				t.Errorf("results = %+v, want %+v", got, tc.want)
			}
			if z.Changed() != tc.changed {
				t.Fatalf("Changed() = %v, want %v", z.Changed(), tc.changed)
			}
			data, changed, err := z.Commit(true)
			if err != nil {
				t.Fatalf("Commit: %v", err)
			}
			if changed != tc.changed || (data == nil) == tc.changed {
				t.Fatalf("Commit = %v bytes, %v", len(data), changed)
			}
			// Purity: the entries as loaded are untouched.
			if !EntriesEqual(before, z.original) {
				t.Error("original entries were modified")
			}
			if !tc.changed {
				// A no-op case: the result is the fixture reformatted, unbumped.
				var buf bytes.Buffer
				if err := Format(&buf, z.apex, z.entries, false); err != nil {
					t.Fatal(err)
				}
				data = buf.Bytes()
			}
			golden := filepath.Join("testdata", "edit", cmp.Or(tc.golden, tc.name)+".golden")
			if *update && tc.golden == "" {
				if err := os.WriteFile(golden, data, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			wantData, err := os.ReadFile(golden)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(data, wantData) {
				t.Errorf("output differs from %s:\n--- got ---\n%s--- want ---\n%s", golden, data, wantData)
			}
			if tc.multi {
				return
			}
			// Idempotence: the same operation on the output changes nothing.
			again, err := Open(data, "")
			if err != nil {
				t.Fatal(err)
			}
			tc.apply(t, again)
			if again.Changed() {
				var buf bytes.Buffer
				_ = Format(&buf, again.apex, again.entries, false)
				t.Errorf("second application changed the zone:\n%s", buf.String())
			}
		})
	}
}

func TestOpenErrors(t *testing.T) {
	fwd, _ := os.ReadFile("testdata/edit/fwd.zone")
	if _, err := Open([]byte("$ORIGIN e.\n@ IN A 192.0.2.1\n"), ""); !errors.Is(err, ErrNoSOA) {
		t.Errorf("no SOA: %v", err)
	}
	noSOA, _ := os.ReadFile("testdata/edit/no-soa.zone")
	if _, err := Open(noSOA, ""); !errors.Is(err, ErrNoSOA) {
		t.Errorf("no SOA fixture: %v", err)
	}
	if _, err := Open([]byte("@ IN SOA ns host 1 2 3 4 5\n"), ""); !errors.Is(err, ErrNoSOA) {
		t.Errorf("relative SOA owner without origin: %v", err)
	}
	if z, err := Open([]byte("@ IN SOA ns host 1 2 3 4 5\n"), "example.org"); err != nil || z.Apex() != "example.org." {
		t.Errorf("hint supplies the origin: %v", err)
	}
	if _, err := Open(fwd, "other.example.com."); !errors.Is(err, ErrApexMismatch) {
		t.Errorf("apex mismatch: %v", err)
	}
	if z, err := Open(fwd, "AT.example.com"); err != nil || z.Apex() != "at.example.com." {
		t.Errorf("matching apex: %v", err)
	}
	var pe *ParseError
	if _, err := Open([]byte(")"), ""); !errors.As(err, &pe) {
		t.Errorf("parse error: %v", err)
	}
	if _, err := Open([]byte("$ORIGIN e.\n@ IN SOA ns host 1 2 3 4 5\n@ IN A 192.0.2.1\n"), ""); err != nil {
		t.Errorf("good zone: %v", err)
	}
}

func TestEditErrors(t *testing.T) {
	z := openFixture(t, "fwd.zone")
	a := rec(t, "x", 0, dns.TypeA, "192.0.2.9")
	for name, err := range map[string]error{
		"replace outside": call(z.Replace(Selector{Owner: "www.example.net."}, []Entry{a}, ReplaceOptions{})),
		"replace empty":   call(z.Replace(Selector{}, []Entry{a}, ReplaceOptions{})),
		"replace anchor":  call(z.Replace(Selector{Owner: "x"}, []Entry{a}, ReplaceOptions{Placement: Placement{{Owner: "www.example.net."}}})),
		"delete":          call(z.Delete(Selector{Owner: "example.net."})),
		"delete owner":    call(z.DeleteOwner("www.example.net.")),
		"addremove":       call(z.AddRemove("www.example.net.", dns.TypeA, nil, nil, nil)),
		"addremove place": call(z.AddRemove("x", dns.TypeA, nil, nil, Placement{{Owner: "example.net."}})),
		"collapse":        call(z.Collapse("www.example.net.", dns.TypeTXT, nil, a, nil)),
		"collapse place":  call(z.Collapse("x", dns.TypeTXT, nil, a, Placement{{Owner: "example.net."}})),
	} {
		if !errors.Is(err, ErrNotInZone) {
			t.Errorf("%s: %v, want ErrNotInZone", name, err)
		}
	}
	if _, err := z.Replace(Selector{Owner: "nothere", Types: []uint16{dns.TypeA}}, []Entry{a}, ReplaceOptions{MustExist: true}); !errors.Is(err, ErrNotFound) {
		t.Errorf("MustExist: %v", err)
	}
	if z.Changed() {
		t.Error("failed operations must not change the zone")
	}
	// An absent delete is a no-op without error.
	if r, err := z.Delete(Selector{Owner: "nothere", Types: []uint16{dns.TypeA}}); err != nil || r != (Result{Index: -1}) || z.Changed() {
		t.Errorf("absent delete: %+v, %v", r, err)
	}
	// Commit refuses what the reference parser rejects.
	bad := rec(t, "bad", 0, dns.TypeA, "not-an-address")
	if _, err := z.Replace(Selector{Owner: "bad", Types: []uint16{dns.TypeA}}, []Entry{bad}, ReplaceOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := z.Commit(false); !errors.Is(err, ErrUnsafeWrite) {
		t.Errorf("Commit of a bad record: %v", err)
	}
	// Commit with nothing changed.
	y := openFixture(t, "fwd.zone")
	if data, changed, err := y.Commit(true); data != nil || changed || err != nil {
		t.Errorf("Commit unchanged = %v, %v, %v", data, changed, err)
	}
}

func call(_ Result, err error) error { return err }

func TestQueries(t *testing.T) {
	z := openFixture(t, "fwd.zone")
	if got := z.Select(Selector{Owner: "loop"}); len(got) != 2 || got[0].Type() != "A" || got[1].Type() != "AAAA" {
		t.Errorf("Select loop = %+v", got)
	}
	if got := z.Select(Selector{Types: []uint16{dns.TypeNS}}); len(got) != 2 {
		t.Errorf("Select NS = %+v", got)
	}
	if got := z.Select(Selector{Owner: "www.example.net."}); got != nil {
		t.Errorf("Select outside = %+v", got)
	}
	if got := z.Owners(Selector{Types: []uint16{dns.TypeNS}}); !slices.Equal(got, []string{"at.example.com."}) {
		t.Errorf("Owners NS = %q", got)
	}
	if got := z.Owners(Selector{Types: []uint16{dns.TypeTXT}, Contents: []string{acmeToken}}); !slices.Equal(got, []string{"_acme-challenge.zot.at.example.com."}) {
		t.Errorf("Owners TXT = %q", got)
	}
	if got := z.Owners(Selector{Owner: "@", Types: []uint16{dns.TypeNS}}); !slices.Equal(got, []string{"at.example.com."}) {
		t.Errorf("Owners @ = %q", got)
	}
	if serial, ok := z.Serial(); !ok || serial != 1763822925 {
		t.Errorf("Serial = %d, %v", serial, ok)
	}
	sets := z.RRSets()
	wantSets := []RRSet{
		{"at.example.com.", "SOA", 60, []string{"ns1.example.com. hostmaster.example.com. 1763822925 1H 600 1W 1D"}},
		{"at.example.com.", "NS", 60, []string{"ns1.example.com.", "ns2.example.com."}},
		{"loop.at.example.com.", "A", 60, []string{"192.0.2.1"}},
		{"loop.at.example.com.", "AAAA", 60, []string{"2001:db8::1"}},
		{"_acme-challenge.zot.at.example.com.", "TXT", 60, []string{acmeToken}},
	}
	if !slices.EqualFunc(sets, wantSets, rrsetEqual) {
		t.Errorf("RRSets = %+v", sets)
	}
	if abs := z.AbsoluteOwner(z.entries[10]); abs != "loop.at.example.com." {
		t.Errorf("AbsoluteOwner = %q", abs)
	}
	if abs := z.AbsoluteOwner(Entry{kind: Record}); abs != "" {
		t.Errorf("AbsoluteOwner of ownerless = %q", abs)
	}
	if len(z.Entries()) != len(z.entries) {
		t.Error("Entries")
	}
	// Ownerless records and unknown TTL in RRSets; non-numeric serial.
	y, err := Open([]byte("example.org. IN SOA ns host abc 2 3 4 5\n IN A 192.0.2.1\nwww 30 IN A 192.0.2.2\n"), "")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := y.Serial(); ok {
		t.Error("non-numeric serial")
	}
	if sets := y.RRSets(); len(sets) != 3 || sets[1].TTL != 0 || sets[2].TTL != 30 {
		t.Errorf("RRSets = %+v", sets)
	}
	if _, ok := (&Zone{}).Serial(); ok {
		t.Error("no SOA serial")
	}
}

func rrsetEqual(a, b RRSet) bool {
	return a.Owner == b.Owner && a.Type == b.Type && a.TTL == b.TTL && slices.Equal(a.Contents, b.Contents)
}

// Spec (edit) 6.3.
func TestContentMatching(t *testing.T) {
	z, err := Open([]byte("$ORIGIN example.org.\n@ IN SOA ns host 1 2 3 4 5\n@ IN MX 10 mx.example.com.\nt IN TXT \"a b\"\nu IN TXT \"a\" \"b\"\nc IN CAA 0 issue \"ca.example\"\np IN PTR host.example.com.\n"), "")
	if err != nil {
		t.Fatal(err)
	}
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
		if got != tc.want {
			t.Errorf("%s %d %q: match = %v, want %v", tc.owner, tc.rtype, tc.content, got, tc.want)
		}
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
		if got := normalizeContent(tc.rtype, tc.in); got != tc.want {
			t.Errorf("normalizeContent(%d, %q) = %q, want %q", tc.rtype, tc.in, got, tc.want)
		}
	}
}

func TestPlacementIndex(t *testing.T) {
	z := openFixture(t, "fwd.zone")
	for _, tc := range []struct {
		p    Placement
		want int
	}{
		{nil, len(z.entries)},
		{Placement{{Owner: "nothere"}}, len(z.entries)},
		{Placement{{Owner: "loop"}}, 12},
		{Placement{{Owner: "nothere"}, {Prefix: "_ACME-challenge."}}, 15},
		{Placement{{Prefix: "_acme-challenge."}, {Owner: "loop"}}, 15},
		{Placement{{}}, len(z.entries)},
		{Placement{{Owner: "@"}}, 8},
	} {
		p, err := z.placement(tc.p)
		if err != nil {
			t.Fatal(err)
		}
		if got := placementIndex(z.entries, p); got != tc.want {
			t.Errorf("placementIndex(%+v) = %d, want %d", tc.p, got, tc.want)
		}
	}
}

// Properties over generated zones (edit spec section 7).
func TestEditProperties(t *testing.T) {
	r := newRand(7, 8)
	for i := range 200 {
		text := "$ORIGIN example.org.\n@ IN SOA ns host 1 2 3 4 5\n" + genZone(r)
		z, err := Open([]byte(text), "")
		if err != nil {
			continue // genZone may produce a second SOA under another origin
		}
		before := z.RRSets()
		comments := allComments(z.entries)
		sets := z.RRSets()
		if len(sets) < 2 {
			continue
		}
		set := sets[1+r.IntN(len(sets)-1)]
		rtype := typeNames[set.Type]
		sel := Selector{Owner: set.Owner, Types: []uint16{rtype}}

		// Replace then Delete removes exactly that set.
		if !InZone(set.Owner, z.apex) {
			continue
		}
		rep := rec(t, "@", 0, dns.TypeTXT, "x")
		if _, err := z.Replace(sel, []Entry{rep}, ReplaceOptions{Mode: ReplaceAll}); err != nil {
			t.Fatalf("#%d Replace: %v\n%s", i, err, text)
		}
		if _, err := z.Delete(Selector{Owner: set.Owner, Types: []uint16{dns.TypeTXT}, Contents: []string{"x"}}); err != nil {
			t.Fatal(err)
		}
		wantSets := slices.DeleteFunc(slices.Clone(before), func(s RRSet) bool { return s.Owner == set.Owner && s.Type == set.Type })
		if !slices.EqualFunc(z.RRSets(), wantSets, rrsetEqual) {
			t.Fatalf("#%d Replace+Delete: got %+v, want %+v\n%s", i, z.RRSets(), wantSets, text)
		}

		// AddRemove add then remove restores the sets.
		y, _ := Open([]byte(text), "")
		add := rec(t, "@", 0, dns.TypeA, "192.0.2.77")
		if _, err := y.AddRemove(set.Owner, dns.TypeA, []Entry{add}, nil, nil); err != nil {
			t.Fatal(err)
		}
		if _, err := y.AddRemove(set.Owner, dns.TypeA, nil, []string{"192.0.2.77"}, nil); err != nil {
			t.Fatal(err)
		}
		if !slices.EqualFunc(y.RRSets(), before, rrsetEqual) || y.Changed() {
			t.Fatalf("#%d AddRemove round trip changed the zone\n%s", i, text)
		}

		// Carried comments: a replace with insertion keeps every comment.
		x, _ := Open([]byte(text), "")
		if _, err := x.Replace(sel, []Entry{rep}, ReplaceOptions{Mode: ReplaceAll}); err != nil {
			t.Fatal(err)
		}
		after := allComments(x.entries)
		for _, c := range comments {
			// Carried comments are joined onto one line, so look inside.
			if !slices.ContainsFunc(after, func(a string) bool { return strings.Contains(a, c) }) {
				t.Fatalf("#%d comment %q lost by Replace\n%s", i, c, text)
			}
		}
		// And the result commits safely.
		if _, _, err := x.Commit(true); err != nil {
			t.Fatalf("#%d Commit: %v\n%s", i, err, text)
		}
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
	f.Add([]byte("@ IN SOA ns host 1 2 3 4 5\n"), "@", "x", uint16(dns.TypeMX))
	f.Fuzz(func(t *testing.T, data []byte, owner, content string, rtype uint16) {
		z, err := Open(data, "")
		if err != nil {
			return
		}
		var records []Entry
		if e, err := NewRecord(owner, 0, rtype, content); err == nil {
			records = []Entry{e}
		}
		sel := Selector{Owner: owner, Types: []uint16{rtype}, Contents: []string{content}}
		p := Placement{{Owner: owner}, {Prefix: content}}
		_, _ = z.Replace(sel, records, ReplaceOptions{Mode: ReplaceAll, Placement: p})
		_, _ = z.Replace(Selector{Owner: owner}, records, ReplaceOptions{Mode: ReplaceFirst, MustExist: true})
		_, _ = z.AddRemove(owner, rtype, records, []string{content}, p)
		if len(records) > 0 {
			_, _ = z.Collapse(owner, rtype, []string{content}, records[0], p)
		}
		_, _ = z.Delete(sel)
		_, _ = z.DeleteOwner(owner)
		_ = z.Select(Selector{})
		_ = z.Owners(sel)
		_ = z.RRSets()
		_, _ = z.Serial()
		if _, _, err := z.Commit(true); err != nil && !errors.Is(err, ErrUnsafeWrite) {
			if !strings.Contains(err.Error(), "SOA has") {
				t.Fatalf("Commit: %v", err)
			}
		}
	})
}
