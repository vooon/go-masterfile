// SPDX-License-Identifier: Apache-2.0

package masterfile

import (
	"bytes"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func plainOf(t *testing.T, e Entry) string {
	t.Helper()
	var b bytes.Buffer
	require.NoError(t, writePlain(&b, "example.org.", "example.org.", []Entry{e}))
	return strings.TrimSuffix(b.String(), "\n")
}

// Spec 8.5.
func TestNewRecord(t *testing.T) {
	for _, tc := range []struct {
		owner string
		ttl   uint32
		rtype uint16
		rdata string
		want  string
	}{
		{"www", 0, dns.TypeA, "192.0.2.1", "www IN A 192.0.2.1"},
		{"www", 300, dns.TypeAAAA, "2001:db8::1", "www 300 IN AAAA 2001:db8::1"},
		{"@", 0, dns.TypeMX, "10   mx.example.org.", "@ IN MX 10 mx.example.org."},
		{"@", 0, dns.TypeCAA, `0 issue "ca.example.net; validationmethods=dns-01"`, `@ IN CAA 0 issue "ca.example.net; validationmethods=dns-01"`},
		{"_acme-challenge", 0, dns.TypeTXT, `tok"en\x`, `_acme-challenge IN TXT "tok\"en\\x"`},
		{"txt", 0, dns.TypeTXT, "with spaces ; not a comment", `txt IN TXT "with spaces ; not a comment"`},
		{"txt", 0, dns.TypeTXT, "a\nb ; ( )", `txt IN TXT "a\010b ; ( )"`},
		{"txt", 0, dns.TypeSPF, "v=spf1 -all", `txt IN SPF "v=spf1 -all"`},
	} {
		e, err := NewRecord(tc.owner, tc.ttl, tc.rtype, tc.rdata)
		if !assert.NoError(t, err, "NewRecord(%q, %d, %d, %q)", tc.owner, tc.ttl, tc.rtype, tc.rdata) {
			continue
		}
		assert.Equal(t, tc.want, plainOf(t, e), "NewRecord(%q, %d, %d, %q)", tc.owner, tc.ttl, tc.rtype, tc.rdata)
		// Round trip: the plain rendering parses back to an equal entry.
		f, err := Parse([]byte(plainOf(t, e)+"\n"), "")
		if !assert.NoError(t, err, "parse back %q", tc.want) {
			continue
		}
		assert.True(t, f.Entries[0].Equal(e), "round trip of %q is not Equal", tc.want)
		assert.NotEmpty(t, e.Content(), "%q: empty Content", tc.want)
	}
	for _, tc := range []struct {
		owner string
		rtype uint16
		rdata string
	}{
		{"www", dns.TypeA, "192.0.2.1\nevil IN A 192.0.2.66"},
		{"www", dns.TypeA, "192.0.2.1 ; evil"},
		{"www", dns.TypeA, "192.0.2.1\n$INCLUDE /etc/passwd"},
		{"www", dns.TypeA, "( 192.0.2.1 )"},
		{"www", dns.TypeA, "192.0.2.1 )"},
		{"@", dns.TypeCAA, `0 issue "ca`},
		{"www", dns.TypeA, ""},
		{"www", dns.TypeA, "   "},
		{"www", dns.TypeTXT, ""},
		{"www", dns.TypeA, "192.0.2.1\x00"},
		{"www", dns.TypeTXT, "a\x00b"},
		{"www", dns.TypeA, "192.0.2.1\r"},
		{"evil IN A 192.0.2.66\nwww", dns.TypeA, "192.0.2.1"},
		{"a b", dns.TypeA, "192.0.2.1"},
		{"", dns.TypeA, "192.0.2.1"},
		{`"www"`, dns.TypeA, "192.0.2.1"},
		{"a;b", dns.TypeA, "192.0.2.1"},
		{"$ORIGIN", dns.TypeA, "192.0.2.1"},
		{"\x00", dns.TypeA, "192.0.2.1"},
		{"www", 65280, "192.0.2.1"},
	} {
		_, err := NewRecord(tc.owner, 0, tc.rtype, tc.rdata)
		assert.ErrorIs(t, err, ErrInvalidRecord, "NewRecord(%q, %d, %q)", tc.owner, tc.rtype, tc.rdata)
	}
}

func parseEntries(t *testing.T, text string) []Entry {
	t.Helper()
	f, err := Parse([]byte(text), "")
	require.NoError(t, err, "Parse(%q)", text)
	return f.Entries
}

// Spec 8.6.
func TestEquality(t *testing.T) {
	a := parseEntries(t, `$TTL 60
www IN A 192.0.2.1
`)
	b := parseEntries(t, `$TTL 60
www 60 IN A 192.0.2.1
`)
	c := parseEntries(t, `$TTL 60
www 1M IN A 192.0.2.1
`)
	d := parseEntries(t, `$TTL 60
www 120 IN A 192.0.2.1
`)
	e := parseEntries(t, `$TTL 120
www IN A 192.0.2.1
`)
	assert.True(t, EntriesEqual(a, b), "a, b, c must be EntriesEqual")
	assert.True(t, EntriesEqual(a, c), "a, b, c must be EntriesEqual")
	assert.True(t, EntriesEqual(b, c), "a, b, c must be EntriesEqual")
	assert.False(t, a[1].Equal(b[1]), "implicit and explicit TTL must not be Entry.Equal")
	assert.False(t, a[1].Equal(c[1]), "implicit and explicit TTL must not be Entry.Equal")
	assert.True(t, b[1].Equal(c[1]), "60 and 1M must be Entry.Equal")
	assert.False(t, EntriesEqual(a, d), "different TTLs must not be EntriesEqual")
	assert.False(t, EntriesEqual(b, d), "different TTLs must not be EntriesEqual")
	assert.False(t, EntriesEqual(a, e), "different TTLs must not be EntriesEqual")
	x := parseEntries(t, `www 60 IN A 192.0.2.1
`)
	y := parseEntries(t, `www IN A 192.0.2.1
`)
	assert.False(t, EntriesEqual(x, y), "known vs unknown effective TTL must differ")
	assert.True(t, EntriesEqual(y, parseEntries(t, `WWW A 192.0.2.1
`)), "case and implicit class must not matter")
	assert.False(t, EntriesEqual(y, parseEntries(t, `www IN A 192.0.2.1

`)), "different lengths must differ")
	assert.False(t, EntriesEqual(parseEntries(t, `; a
`), parseEntries(t, `; b
`)), "different comments must differ")
	assert.False(t, EntriesEqual(parseEntries(t, `$ORIGIN a.
`), parseEntries(t, `$ORIGIN b.
`)), "different directives must differ")
	assert.False(t, EntriesEqual(parseEntries(t, "\n"), parseEntries(t, `; c
`)), "different kinds must differ")
	assert.True(t, EntriesEqual(parseEntries(t, `
; c
$TTL 1h
`), parseEntries(t, `
; c
$TTL 3600
`)), "equal non-records must be equal")
	txt := parseEntries(t, `t IN TXT "a b"
`)
	assert.True(t, txt[0].Equal(parseEntries(t, `t TXT a\ b
`)[0]), "decoded values must compare equal regardless of quoting")
	assert.False(t, txt[0].Equal(parseEntries(t, `t IN TXT "a c"
`)[0]), "different values must differ")
	assert.False(t, txt[0].Equal(parseEntries(t, `t IN SPF "a b"
`)[0]), "different types must differ")
	assert.False(t, txt[0].Equal(parseEntries(t, `t CH TXT "a b"
`)[0]), "different classes must differ")
}

// Spec 8.7.
func TestNames(t *testing.T) {
	for _, tc := range []struct{ name, origin, want string }{
		{"www.example.org.", "example.org.", "www"},
		{"example.org.", "example.org.", "@"},
		{"WWW.Example.ORG.", "example.org.", "WWW"},
		{"other.org.", "example.org.", "other.org."},
		{"myexample.org.", "example.org.", "myexample.org."},
		{"www", "example.org.", "www"},
		{"@", "example.org.", "@"},
		{`a\.example.org.`, "example.org.", `a\.example.org.`},
		{"www.example.org.", "", "www.example.org."},
		{"www.example.org.", ".", "www.example.org"},
		{".", ".", "@"},
		{"..", ".", ".."},
		{"...", ".", "..."},
		{"a..", ".", "a.."},
		{"www.example.org.", "example.org", "www"},
	} {
		assert.Equal(t, tc.want, Relative(tc.name, tc.origin), "Relative(%q, %q)", tc.name, tc.origin)
	}
	for _, tc := range []struct{ name, origin, want string }{
		{"www", "example.org.", "www.example.org."},
		{"www", "example.org", "www.example.org."},
		{"@", "example.org.", "example.org."},
		{"@", "", ""},
		{"www.", "example.org.", "www."},
		{"www", "", "www."},
		{"www", ".", "www."},
		{`a\.`, "example.org.", `a\..example.org.`},
	} {
		assert.Equal(t, tc.want, Absolute(tc.name, tc.origin), "Absolute(%q, %q)", tc.name, tc.origin)
	}
	assert.Equal(t, "a.", Fqdn("a"))
	assert.Equal(t, "a.", Fqdn("a."))
	assert.Equal(t, ".", Fqdn(""))
	assert.Equal(t, `a\..`, Fqdn(`a\.`))
	assert.True(t, NameEqual("WwW", "www"))
	assert.False(t, NameEqual("www", "www."))
	assert.False(t, NameEqual("é", "É"))
}

func TestParseApex(t *testing.T) {
	for _, tc := range []struct {
		text, hint, apex string
		soa, complete    bool
	}{
		{`$ORIGIN example.org.
@ IN SOA a b 1 2 3 4 5
`, "", "example.org.", true, true},
		{`example.org. IN SOA a b 1 2 3 4 5
`, "", "example.org.", true, true},
		{`@ IN SOA a b 1 2 3 4 5
`, "example.org", "example.org.", true, true},
		{`$ORIGIN example.org.
sub IN SOA a b 1 2 3 4 5
`, "", "sub.example.org.", true, true},
		{`$ORIGIN example.org.
www IN A 192.0.2.1
`, "", "example.org.", false, false},
		{`www IN A 192.0.2.1
`, "", ".", false, false},
		{`@ IN SOA a b 1 2 3 4 5
`, "", ".", true, false},
		{`www IN A 192.0.2.1
`, "example.org", "example.org.", false, false},
		{`$ORIGIN example.org.
www IN A 192.0.2.1
 IN SOA a b 1 2 3 4 5
`, "", "www.example.org.", true, true},
		{`$ORIGIN example.org.
 IN SOA a b 1 2 3 4 5
`, "", "example.org.", true, true},
		{`$ORIGIN sub.example.org.
www IN A 192.0.2.1
`, "example.org", "example.org.", false, false},
		{`$ORIGIN example.org.
 IN SOA a b 1 2 3 4 5
`, "other.org", "other.org.", true, true},
		{"", "", ".", false, false},
	} {
		z, err := Parse([]byte(tc.text), tc.hint)
		require.NoError(t, err, "Parse(%q, %q)", tc.text, tc.hint)
		assert.Equal(t, tc.apex, z.Apex(), "Parse(%q, %q).Apex()", tc.text, tc.hint)
		soa, ok := z.SOA()
		assert.Equal(t, tc.soa, ok, "Parse(%q): SOA() = %v, %v", tc.text, soa, ok)
		if ok {
			assert.Equal(t, "SOA", soa.Type(), "Parse(%q): SOA() = %v, %v", tc.text, soa, ok)
		}
		if err := z.Check(); tc.complete {
			assert.NoError(t, err, "Parse(%q, %q).Check()", tc.text, tc.hint)
		} else {
			assert.Error(t, err, "Parse(%q, %q).Check()", tc.text, tc.hint)
		}
	}
	for _, text := range []string{`$ORIGIN a.
@ IN SOA ns host 1 2 3 4 5
`, `b. IN SOA ns host 1 2 3 4 5
`, `$ORIGIN x.
@ IN SOA ns host 1 2 3 4 5
`} {
		_, err := Parse([]byte(text), "sub.a.")
		assert.ErrorIs(t, err, ErrApexMismatch, "Parse(%q, sub.a.)", text)
	}
	assert.ErrorIs(t, New("").Check(), ErrNoOrigin, `New("").Check()`)
	assert.ErrorIs(t, New("example.org").Check(), ErrNoSOA, "New(example.org).Check()")
	z := New("example.org")
	assert.Equal(t, "example.org.", z.Apex(), "New = %+v", z)
	assert.False(t, z.Changed, "New = %+v", z)
	assert.Empty(t, z.Entries, "New = %+v", z)
}

func TestResolveOwners(t *testing.T) {
	f, err := Parse([]byte(`$ORIGIN example.org.
@ IN SOA a b 1 2 3 4 5
 IN NS ns
www IN A 192.0.2.1
 IN AAAA 2001:db8::1
other.org. IN A 192.0.2.2
$ORIGIN sub.example.org.
host IN A 192.0.2.3
`), "example.org.")
	require.NoError(t, err)
	var owners []string
	for _, e := range f.Records() {
		owners = append(owners, e.Owner())
	}
	assert.Equal(t, "@ @ www www other.org. host.sub", strings.Join(owners, " "), "owners")
	g, err := Parse([]byte(` IN A 192.0.2.1
www IN A 192.0.2.2
`), "example.org.")
	require.NoError(t, err, "ownerless first record")
	assert.Empty(t, g.Entries[0].Owner(), "ownerless first record")
	assert.Equal(t, "www", g.Entries[1].Owner(), "ownerless first record")
	h, err := Parse([]byte(`@ IN A 192.0.2.1
`), "")
	require.NoError(t, err, "@ without origin")
	assert.Equal(t, ".", h.Apex(), "@ without origin: %+v", h)
	assert.Equal(t, "@", h.Entries[0].Owner(), "@ without origin: %+v", h)
	// Stop the iterator early.
	n := 0
	for range f.Records() {
		n++
		break
	}
	assert.Equal(t, 1, n, "Records iterator did not stop")
}

func TestStringToTTL(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want uint32
		ok   bool
	}{
		{"0", 0, true}, {"90", 90, true}, {"1h30m", 5400, true}, {"2W", 1209600, true},
		{"1d12h", 129600, true}, {"1h30", 3630, true}, {"1s", 1, true}, {"4294967295", 4294967295, true},
		{"", 0, false}, {"4294967296", 0, false}, {"1x", 0, false}, {"h", 0, false}, {"1hh", 0, false},
		{"-1", 0, false}, {"99999999w", 0, false}, {"1 h", 0, false},
	} {
		got, ok := StringToTTL(tc.in)
		assert.Equal(t, tc.want, got, "StringToTTL(%q)", tc.in)
		assert.Equal(t, tc.ok, ok, "StringToTTL(%q)", tc.in)
	}
}

func TestQuote(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"", `""`},
		{"plain", `"plain"`},
		{`a"b\c`, `"a\"b\\c"`},
		{"tab\there", `"tab\009here"`},
		{"nl\n\x7f\x00", `"nl\010\127\000"`},
		{"ünïcödé \xff", "\"ünïcödé \xff\""},
	} {
		got := Quote(tc.in)
		assert.Equal(t, tc.want, got, "Quote(%q)", tc.in)
		f, err := Parse([]byte("t IN TXT "+got+"\n"), "")
		if assert.NoError(t, err, "Quote(%q) does not read back", tc.in) {
			assert.Equal(t, tc.in, f.Entries[0].Values()[0], "Quote(%q) does not read back", tc.in)
		}
	}
}

func TestEntryAccessors(t *testing.T) {
	es := parseEntries(t, `; top

$TTL 1h ; default
www 300 IN TXT ( ; head
 "a" ; one
 "b" ) ; end
`)
	require.Len(t, es, 4, "kinds: %v", es)
	require.Equal(t, Comment, es[0].Kind(), "kinds: %v", es)
	require.Equal(t, Blank, es[1].Kind(), "kinds: %v", es)
	require.Equal(t, Directive, es[2].Kind(), "kinds: %v", es)
	require.Equal(t, Record, es[3].Kind(), "kinds: %v", es)
	assert.Equal(t, "; top", es[0].Comment(), "comment entry")
	assert.Equal(t, 1, es[0].Line(), "comment entry")
	assert.Equal(t, "kind(9)", Kind(9).String())
	assert.Equal(t, "record", Record.String())
	d := es[2]
	assert.Equal(t, "$TTL", d.Name(), "directive entry: %+v", d)
	assert.Equal(t, "1h", d.Args()[0].Raw, "directive entry: %+v", d)
	assert.Equal(t, "; default", strings.Join(d.Comments(), ","), "directive entry: %+v", d)
	assert.Equal(t, "1h", d.RawValues()[0], "directive entry: %+v", d)
	assert.Equal(t, 3, d.Line(), "directive entry: %+v", d)
	r := es[3]
	ttl, ok := r.TTL()
	assert.Equal(t, "www", r.Owner(), "record header: %+v", r)
	assert.True(t, ok, "record header: %+v", r)
	assert.Equal(t, uint32(300), ttl.Seconds, "record header: %+v", r)
	assert.Equal(t, "300", ttl.Raw, "record header: %+v", r)
	assert.Equal(t, "IN", r.Class(), "record header: %+v", r)
	assert.Equal(t, "TXT", r.Type(), "record header: %+v", r)
	assert.Equal(t, dns.TypeTXT, r.RType(), "record header: %+v", r)
	assert.Equal(t, 4, r.Line(), "record header: %+v", r)
	assert.Equal(t, "; head,; one,; end", strings.Join(r.Comments(), ","), "comments")
	assert.Equal(t, "; head", strings.Join(r.Head(), ","), "head")
	assert.Equal(t, "; end", strings.Join(r.Tail(), ","), "tail")
	fs := r.Fields()
	require.Len(t, fs, 2, "fields = %+v", fs)
	assert.True(t, fs[0].Quoted, "fields = %+v", fs)
	assert.Equal(t, "; one", fs[0].Comments[0], "fields = %+v", fs)
	assert.Nil(t, fs[1].Comments, "fields = %+v", fs)
	fs[0].Comments[0] = "mutated"
	assert.Equal(t, "; one", r.Fields()[0].Comments[0], "Fields() must return a copy")
	assert.Equal(t, "ab", r.Content(), "values")
	assert.Equal(t, `"a","b"`, strings.Join(r.RawValues(), ","), "values")
	assert.Equal(t, "a,b", strings.Join(r.Values(), ","), "values")
	w := r.WithComments("note", "; two", " ")
	assert.Equal(t, "; end,; note ; two", strings.Join(w.Tail(), ","), "WithComments tail")
	assert.Equal(t, "; end", strings.Join(r.Tail(), ","), "WithComments must not alias or change the original")
	assert.True(t, r.WithComments().Equal(r), "WithComments must not alias or change the original")
	assert.Equal(t, "; top ; x", es[0].WithComments("x").Comment(), "WithComments on comment/blank")
	assert.Equal(t, "; x", es[1].WithComments("x").Comment(), "WithComments on comment/blank")
	assert.Equal(t, Comment, es[1].WithComments("x").Kind(), "WithComments on comment/blank")
	assert.Equal(t, "other", r.WithOwner("other").Owner(), "WithOwner")
	assert.Equal(t, "www", r.Owner(), "WithOwner")
	assert.Empty(t, r.WithOwner("").Owner(), "WithOwner")
	var zero Entry
	assert.Equal(t, Blank, zero.Kind(), "zero entry")
	assert.Empty(t, zero.Values(), "zero entry")
	assert.Empty(t, zero.Comments(), "zero entry")
	assert.Empty(t, zero.Content(), "zero entry")
	mx := parseEntries(t, `@ MX 10 mail
`)[0]
	assert.Equal(t, "10 mail", mx.Content(), "MX content/class")
	assert.Empty(t, mx.Class(), "MX content/class")
	assert.Equal(t, "IN", mx.classOrDefault(), "MX content/class")
}

func TestParseDetails(t *testing.T) {
	es := parseEntries(t, "a\tIN\tA\t192.0.2.1\r\n\r\n\r\n\n  ; indented\r\nb type65280 \\# 1 00\nc class3 TYPE1 x\nd 1H IN A x\ne IN 1h A x\n$include other.zone\n$GENERATE 1-10 h$ A 192.0.2.$ ; gen\n$origin foo ; o\n$TTL 1h\n\n\n")
	require.Len(t, es, 12, "entries: %+v", es)
	assert.Equal(t, Blank, es[1].Kind(), "blank/comment: %+v", es[1:3])
	assert.Equal(t, Comment, es[2].Kind(), "blank/comment: %+v", es[1:3])
	assert.Equal(t, "; indented", es[2].Comment(), "blank/comment: %+v", es[1:3])
	e := es[3]
	assert.Equal(t, "TYPE65280", e.Type(), "TYPE65280: %+v", e)
	assert.Equal(t, uint16(65280), e.RType(), "TYPE65280: %+v", e)
	assert.Equal(t, "b.", e.Owner(), "TYPE65280: no origin before it, so taken as absolute: %+v", e)
	assert.Equal(t, `\# 1 00`, strings.Join(e.RawValues(), " "), "TYPE65280: %+v", e)
	e = es[4]
	assert.Equal(t, "CLASS3", e.Class(), "class3/TYPE1: %+v", e)
	assert.Equal(t, "TYPE1", e.Type(), "class3/TYPE1: %+v", e)
	assert.Equal(t, uint16(1), e.RType(), "class3/TYPE1: %+v", e)
	_, ok := es[5].TTL()
	assert.True(t, ok, "ttl before class")
	assert.Equal(t, "IN", es[5].Class(), "ttl before class")
	_, ok = es[6].TTL()
	assert.True(t, ok, "class before ttl")
	assert.Equal(t, "IN", es[6].Class(), "class before ttl")
	assert.Equal(t, "$INCLUDE", es[7].Name(), "directives: %+v", es[7:])
	assert.Equal(t, "$GENERATE", es[8].Name(), "directives: %+v", es[7:])
	assert.Equal(t, "; gen", strings.Join(es[8].Tail(), ""), "directives: %+v", es[7:])
	assert.Equal(t, "$ORIGIN", es[9].Name(), "directives: %+v", es[7:])
	assert.Equal(t, "$TTL", es[10].Name(), "directives: %+v", es[7:])
	last := es[len(es)-1]
	assert.Equal(t, Blank, last.Kind(), "trailing blank lines must be kept as one entry: %+v", last)
	assert.Equal(t, 14, last.Line(), "trailing blank lines must be kept as one entry: %+v", last)
	// A final line without terminator.
	if es := parseEntries(t, "a IN A 1"); assert.Len(t, es, 1, "no final newline") {
		assert.Equal(t, "a", es[0].Owner(), "no final newline")
	}
	// Empty input.
	assert.Empty(t, parseEntries(t, ""), "empty input")
	// Comments in every position of a multi-line record.
	es = parseEntries(t, `a IN TXT ( ; h1
 ; h2
 "x" ; fx
 ; fx2
 "y" ) ; t
`)
	e = es[0]
	assert.Equal(t, "; h1,; h2", strings.Join(e.Head(), ","), "comment positions: %+v", e)
	assert.Equal(t, "; fx,; fx2", strings.Join(e.Fields()[0].Comments, ","), "comment positions: %+v", e)
	assert.Equal(t, "; t", strings.Join(e.Tail(), ","), "comment positions: %+v", e)
	// Zero-field record with a comment keeps it as tail.
	e = parseEntries(t, `a IN A ; none
`)[0]
	assert.Empty(t, e.Head(), "zero-field comment: %+v", e)
	assert.Equal(t, "; none", strings.Join(e.Tail(), ""), "zero-field comment: %+v", e)
	// Escapes in items.
	e = parseEntries(t, `a\;b\ c IN TXT d\\e\032
`)[0]
	assert.Equal(t, `a\;b\ c`, e.Owner(), "item escapes: %+v", e)
	assert.Equal(t, `d\e `, e.Values()[0], "item escapes: %+v", e)
	assert.Equal(t, `d\\e\032`, e.RawValues()[0], "item escapes: %+v", e)
	// Blank-led line without previous owner still parses.
	e = parseEntries(t, `  IN A 192.0.2.1
`)[0]
	assert.Empty(t, e.Owner(), "inherited owner: %+v", e)
	assert.Equal(t, "A", e.Type(), "inherited owner: %+v", e)
	// Opaque high bytes are kept.
	e = parseEntries(t, "xn--\xc3\xa9 IN TXT \"\xff\"\n")[0]
	assert.Equal(t, "xn--\xc3\xa9", e.Owner(), "high bytes: %+v", e)
	assert.Equal(t, "\xff", e.Values()[0], "high bytes: %+v", e)
	// Parse error line numbers.
	_, err := Parse([]byte(`a IN A 1
b IN A 2
$NOPE
`), "")
	var pe *ParseError
	require.ErrorAs(t, err, &pe, "error = %v", err)
	assert.Equal(t, 3, pe.Line, "error = %v", err)
	assert.Equal(t, 1, pe.Col, "error = %v", err)
	assert.Equal(t, "line 3: unknown directive $NOPE", pe.Error())
	_, err = Parse([]byte(`a IN A 1 ; c
 IN`), "")
	require.ErrorAs(t, err, &pe, "error = %v", err)
	assert.Equal(t, 2, pe.Line, "error = %v", err)
	assert.Equal(t, "missing type", pe.Msg, "error = %v", err)
}
