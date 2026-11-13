// SPDX-License-Identifier: Apache-2.0

package masterfile

import (
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// commit applies nothing more: it renders the zone through Commit, which
// also runs Verify, and returns the text.
func commit(t *testing.T, z *Zone) string {
	t.Helper()
	z.Changed = true
	data, _, err := z.Commit(false)
	require.NoError(t, err, "Commit")
	return string(data)
}

func parse(t *testing.T, text, apex string) *Zone {
	t.Helper()
	z, err := Parse([]byte(text), apex)
	require.NoError(t, err, "Parse")
	return z
}

const soaLine = "example.org. IN SOA ns.example.org. h.example.org. 1 2 3 4 5\n"

const soaBlock = `example.org.     IN SOA ns.example.org. h.example.org. (
    1 ; serial  Thu, 01 Jan 1970 00:00:01 UTC
    2 ; refresh
    3 ; retry
    4 ; expire
    5 ; minimum
)
`

// A file without $ORIGIN, parsed without an apex, is rendered against the
// root. Owners written absolute must keep their dot, or a name server
// loading the file under the zone's origin reads different names.
func TestOwnerSpellingWithoutOrigin(t *testing.T) {
	in := "$TTL 60\n" + soaLine + `www.example.org. IN A 192.0.2.1
mail IN A 192.0.2.2
. IN NS ns.example.org.
`
	want := "$TTL 60\n" + soaBlock + `www.example.org. IN A   192.0.2.1
mail             IN A   192.0.2.2
.                IN NS  ns.example.org.
`
	got := reformat(t, in, "", false)
	assert.Equal(t, want, got)
	assert.Equal(t, got, reformat(t, got, "", false), "not idempotent")

	t.Run("inserted record is absolute", func(t *testing.T) {
		z := parse(t, in, "")
		apply(t, z, Insert{Owner: "api", Records: []RR{rr(dns.TypeA, "192.0.2.7")}})
		assert.Contains(t, commit(t, z), "\napi.example.org. IN A   192.0.2.7\n")
	})
	t.Run("inherited owner is spelled like the one it repeats", func(t *testing.T) {
		z := parse(t, "www.example.org. IN A 192.0.2.1\n IN A 192.0.2.2\n", "")
		z.Entries = z.Entries[1:]
		assert.Equal(t, "www.example.org. IN A 192.0.2.2\n", commit(t, z))
	})
	t.Run("zone without a known apex keeps bare names", func(t *testing.T) {
		z := parse(t, "www IN A 192.0.2.1\n", "")
		apply(t, z, Insert{Owner: "api", Records: []RR{rr(dns.TypeA, "192.0.2.7")}})
		assert.Equal(t, "www IN A 192.0.2.1\napi IN A 192.0.2.7\n", commit(t, z))
	})
}

// The origin a $ORIGIN line puts in force is a name in written form: its
// escapes must survive when it is written back as an owner.
func TestOriginWithEscapes(t *testing.T) {
	t.Run("escaped dot", func(t *testing.T) {
		in := `$ORIGIN a\.b.example.
@ IN SOA ns h 1 2 3 4 5
$ORIGIN other.example.
 IN NS ns.other.example.
`
		z := parse(t, in, "")
		assert.Equal(t, `a\.b.example.`, z.Apex())
		got := commit(t, z)
		assert.Contains(t, got, "\n"+`a\.b.example. IN NS  ns.other.example.`+"\n")
		assert.Equal(t, got, reformat(t, got, "", false), "not idempotent")
	})
	t.Run("escaped blanks cannot become a record", func(t *testing.T) {
		in := `$ORIGIN a\ IN\ A\ 192.0.2.9\ \;.
@ IN NS ns.example.org.
$ORIGIN example.org.
 IN NS ns2.example.org.
`
		z := parse(t, in, "")
		got := commit(t, z)
		assert.Contains(t, got, "\n"+`a\ IN\ A\ 192.0.2.9\ \;. IN NS ns2.example.org.`+"\n")
		again := parse(t, got, "")
		assert.Len(t, again.Select(Selector{}), 2)
		assert.Empty(t, again.Select(Selector{Types: []uint16{dns.TypeA}}))
	})
	t.Run("quoted argument is written as a name, once", func(t *testing.T) {
		got := reformat(t, "$ORIGIN \"example.org\"\nwww IN A 192.0.2.1\n", "", false)
		assert.Equal(t, "$ORIGIN example.org.\nwww IN A 192.0.2.1\n", got)
		assert.Equal(t, got, reformat(t, got, "", false), "not idempotent")

		got = reformat(t, "$ORIGIN \"a b;(c)\\.d\"\n@ IN A 192.0.2.1\n", "", false)
		assert.Equal(t, "$ORIGIN a\\ b\\;\\(c\\)\\.d.\n@ IN A 192.0.2.1\n", got)
		assert.Equal(t, got, reformat(t, got, "", false), "not idempotent")
	})
}

// "@" as a label is not the apex marker.
func TestAtLabelIsNotTheApex(t *testing.T) {
	assert.Equal(t, "@.example.org.", Relative("@.example.org.", "example.org."))
	assert.Equal(t, "@.", Relative("@.", "."))
	assert.Equal(t, "@.www", Relative("@.www.example.org.", "example.org."))

	in := "$ORIGIN example.org.\n@ IN SOA ns h 1 2 3 4 5\n@.example.org. IN A 192.0.2.2\n"
	z := parse(t, in, "")
	assert.Contains(t, commit(t, z), "\n@.example.org. IN A   192.0.2.2\n")
	rs := apply(t, z, DeleteOwner{Owner: "@.example.org."})
	assert.Equal(t, 1, rs[0].Removed)
	_, ok := z.SOA()
	assert.True(t, ok, "the SOA must survive")
}

func TestIncreaseWraps(t *testing.T) {
	withClock(t, 1700000000)
	assert.Equal(t, "1700000000", Increase("4294967295"))
	assert.Equal(t, "4294967001", Increase("4294967000"))
	withClock(t, 0)
	assert.Equal(t, "0", Increase("4294967295"))
	withClock(t, 1<<33) // a clock beyond 32 bits is not a serial
	assert.Equal(t, "6", Increase("5"))

	withClock(t, 1700000000)
	z := parse(t, "$ORIGIN example.org.\n@ IN SOA ns h 4294967295 2 3 4 5\n", "")
	z.Changed = true
	data, _, err := z.Commit(true)
	require.NoError(t, err)
	assert.Contains(t, string(data), "    1700000000 ; serial")
}

func TestAppendBeforeTrailingBlank(t *testing.T) {
	z := parse(t, "$ORIGIN example.org.\na IN A 192.0.2.2\n\n", "")
	apply(t, z, Replace{Selector: sel("b", dns.TypeA), Records: []RR{rr(dns.TypeA, "192.0.2.3")}})
	assert.Equal(t, "$ORIGIN example.org.\na IN A 192.0.2.2\nb IN A 192.0.2.3\n", commit(t, z))

	t.Run("a trailing comment stays above", func(t *testing.T) {
		z := parse(t, "$ORIGIN example.org.\na IN A 192.0.2.2\n\n; end\n\n", "")
		apply(t, z, Insert{Owner: "_x", Records: []RR{rr(dns.TypeTXT, "v")}})
		assert.Equal(t, "$ORIGIN example.org.\na  IN A   192.0.2.2\n\n; end\n_x IN TXT \"v\"\n", commit(t, z))
	})
}

func TestAddRemoveCarriesComments(t *testing.T) {
	const in = "$ORIGIN example.org.\na IN A 192.0.2.2 ; keep me\na IN A 192.0.2.3 ; other\n"
	z := parse(t, in, "")
	apply(t, z, AddRemove{Owner: "a", Type: dns.TypeA, Remove: []string{"192.0.2.2"}, Add: []string{"192.0.2.9", "192.0.2.10"}})
	assert.Equal(t, `$ORIGIN example.org.
a IN A 192.0.2.3 ; other
  IN A 192.0.2.9 ; keep me
  IN A 192.0.2.10
`, commit(t, z))

	t.Run("nothing added: comments go with the entries", func(t *testing.T) {
		z := parse(t, in, "")
		apply(t, z, AddRemove{Owner: "a", Type: dns.TypeA, Remove: []string{"192.0.2.2"}})
		assert.Equal(t, "$ORIGIN example.org.\na IN A 192.0.2.3 ; other\n", commit(t, z))
	})
}

func TestInsertSkipsRepeatsAndKeepsSpelling(t *testing.T) {
	z := parse(t, "$ORIGIN example.org.\nWWW IN A 192.0.2.2\n", "")
	rs := apply(t, z, Insert{Owner: "www", Records: []RR{
		rr(dns.TypeA, "192.0.2.3"), rr(dns.TypeA, "192.0.2.3"), rr(dns.TypeA, "192.0.2.2"),
	}})
	assert.Equal(t, Result{Matched: 1, Inserted: 1, Index: 2, Changed: true}, rs[0])
	assert.Equal(t, "WWW", z.Entries[2].Owner())
	assert.Equal(t, "$ORIGIN example.org.\nWWW IN A 192.0.2.2\n    IN A 192.0.2.3\n", commit(t, z))
}

// A type written as TYPE<n> is the same type as its name.
func TestNumericTypeSpelling(t *testing.T) {
	z := parse(t, `$ORIGIN example.org.
a IN TYPE1 192.0.2.1
a IN A 192.0.2.2
t IN TYPE16 "a b" "c"
g IN TYPE16 \# 2 0161
`, "")
	sets := z.RRSets()
	require.Len(t, sets, 3)
	assert.Equal(t, RRSet{Owner: "a.example.org.", Type: "A", Contents: []string{"192.0.2.1", "192.0.2.2"}}, sets[0])
	assert.Equal(t, RRSet{Owner: "t.example.org.", Type: "TXT", Contents: []string{"a bc"}}, sets[1])
	assert.Equal(t, []string{"# 2 0161"}, sets[2].Contents, "generic rdata is opaque")
	assert.Len(t, z.Select(Selector{Owner: "t", Types: []uint16{dns.TypeTXT}, Contents: []string{"a bc"}}), 1)

	u := parse(t, "$ORIGIN example.org.\nu IN TYPE65280 \\# 1 00\n", "")
	assert.Equal(t, "TYPE65280", u.RRSets()[0].Type, "a type without a name keeps its spelling")
	assert.Equal(t, `$ORIGIN example.org.
a IN TYPE1  192.0.2.1
  IN A      192.0.2.2
t IN TYPE16 (
    "a b"
    "c"
)
g IN TYPE16 \# 2 0161
`, commit(t, z))
}
