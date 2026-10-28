// SPDX-License-Identifier: Apache-2.0

package masterfile

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func plainOf(t *testing.T, e Entry) string {
	t.Helper()
	var b bytes.Buffer
	if err := WritePlain(&b, "example.org.", []Entry{e}); err != nil {
		t.Fatal(err)
	}
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
		if err != nil {
			t.Errorf("NewRecord(%q, %d, %d, %q): %v", tc.owner, tc.ttl, tc.rtype, tc.rdata, err)
			continue
		}
		if got := plainOf(t, e); got != tc.want {
			t.Errorf("NewRecord(%q, %d, %d, %q) = %q, want %q", tc.owner, tc.ttl, tc.rtype, tc.rdata, got, tc.want)
		}
		// Round trip: the plain rendering parses back to an equal entry.
		f, err := Parse([]byte(plainOf(t, e) + "\n"))
		if err != nil {
			t.Errorf("parse back %q: %v", tc.want, err)
			continue
		}
		if !f.Entries[0].Equal(e) {
			t.Errorf("round trip of %q is not Equal", tc.want)
		}
		if e.Content() == "" {
			t.Errorf("%q: empty Content", tc.want)
		}
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
		if !errors.Is(err, ErrInvalidRecord) {
			t.Errorf("NewRecord(%q, %d, %q) = %v, want ErrInvalidRecord", tc.owner, tc.rtype, tc.rdata, err)
		}
	}
}

func parseEntries(t *testing.T, text string) []Entry {
	t.Helper()
	f, err := Parse([]byte(text))
	if err != nil {
		t.Fatalf("Parse(%q): %v", text, err)
	}
	return f.Entries
}

// Spec 8.6.
func TestEquality(t *testing.T) {
	a := parseEntries(t, "$TTL 60\nwww IN A 192.0.2.1\n")
	b := parseEntries(t, "$TTL 60\nwww 60 IN A 192.0.2.1\n")
	c := parseEntries(t, "$TTL 60\nwww 1M IN A 192.0.2.1\n")
	d := parseEntries(t, "$TTL 60\nwww 120 IN A 192.0.2.1\n")
	e := parseEntries(t, "$TTL 120\nwww IN A 192.0.2.1\n")
	if !EntriesEqual(a, b) || !EntriesEqual(a, c) || !EntriesEqual(b, c) {
		t.Error("a, b, c must be EntriesEqual")
	}
	if a[1].Equal(b[1]) || a[1].Equal(c[1]) {
		t.Error("implicit and explicit TTL must not be Entry.Equal")
	}
	if !b[1].Equal(c[1]) {
		t.Error("60 and 1M must be Entry.Equal")
	}
	if EntriesEqual(a, d) || EntriesEqual(b, d) || EntriesEqual(a, e) {
		t.Error("different TTLs must not be EntriesEqual")
	}
	x := parseEntries(t, "www 60 IN A 192.0.2.1\n")
	y := parseEntries(t, "www IN A 192.0.2.1\n")
	if EntriesEqual(x, y) {
		t.Error("known vs unknown effective TTL must differ")
	}
	if !EntriesEqual(y, parseEntries(t, "WWW A 192.0.2.1\n")) {
		t.Error("case and implicit class must not matter")
	}
	if EntriesEqual(y, parseEntries(t, "www IN A 192.0.2.1\n\n")) {
		t.Error("different lengths must differ")
	}
	if EntriesEqual(parseEntries(t, "; a\n"), parseEntries(t, "; b\n")) {
		t.Error("different comments must differ")
	}
	if EntriesEqual(parseEntries(t, "$ORIGIN a.\n"), parseEntries(t, "$ORIGIN b.\n")) {
		t.Error("different directives must differ")
	}
	if EntriesEqual(parseEntries(t, "\n"), parseEntries(t, "; c\n")) {
		t.Error("different kinds must differ")
	}
	if !EntriesEqual(parseEntries(t, "\n; c\n$TTL 1h\n"), parseEntries(t, "\n; c\n$TTL 3600\n")) {
		t.Error("equal non-records must be equal")
	}
	txt := parseEntries(t, `t IN TXT "a b"`+"\n")
	if !txt[0].Equal(parseEntries(t, `t TXT a\ b`+"\n")[0]) {
		t.Error("decoded values must compare equal regardless of quoting")
	}
	if txt[0].Equal(parseEntries(t, `t IN TXT "a c"`+"\n")[0]) || txt[0].Equal(parseEntries(t, `t IN SPF "a b"`+"\n")[0]) {
		t.Error("different values or types must differ")
	}
	if txt[0].Equal(parseEntries(t, `t CH TXT "a b"`+"\n")[0]) {
		t.Error("different classes must differ")
	}
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
		if got := Relative(tc.name, tc.origin); got != tc.want {
			t.Errorf("Relative(%q, %q) = %q, want %q", tc.name, tc.origin, got, tc.want)
		}
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
		if got := Absolute(tc.name, tc.origin); got != tc.want {
			t.Errorf("Absolute(%q, %q) = %q, want %q", tc.name, tc.origin, got, tc.want)
		}
	}
	if Fqdn("a") != "a." || Fqdn("a.") != "a." || Fqdn("") != "." || Fqdn(`a\.`) != `a\..` {
		t.Error("Fqdn")
	}
	if !NameEqual("WwW", "www") || NameEqual("www", "www.") || NameEqual("é", "É") {
		t.Error("NameEqual")
	}
}

func TestOrigin(t *testing.T) {
	for _, tc := range []struct{ text, hint, apex string }{
		{"$ORIGIN example.org.\n@ IN SOA a b 1 2 3 4 5\n", "", "example.org."},
		{"example.org. IN SOA a b 1 2 3 4 5\n", "", "example.org."},
		{"@ IN SOA a b 1 2 3 4 5\n", "example.org", "example.org."},
		{"$ORIGIN example.org.\nsub IN SOA a b 1 2 3 4 5\n", "", "sub.example.org."},
		{"$ORIGIN example.org.\nwww IN A 192.0.2.1\n", "", "example.org."},
		{"www IN A 192.0.2.1\n", "", ""},
		{"@ IN SOA a b 1 2 3 4 5\n", "", ""},
		{"www IN A 192.0.2.1\n", "example.org", "example.org."},
		{"$ORIGIN example.org.\nwww IN A 192.0.2.1\n IN SOA a b 1 2 3 4 5\n", "", "www.example.org."},
		{"$ORIGIN example.org.\n IN SOA a b 1 2 3 4 5\n", "", ""},
	} {
		f := &File{Entries: parseEntries(t, tc.text)}
		apex, soa := f.Origin(tc.hint)
		if apex != tc.apex {
			t.Errorf("Origin(%q, hint %q) = %q, want %q", tc.text, tc.hint, apex, tc.apex)
		}
		if hasSOA := strings.Contains(tc.text, "SOA"); (soa != nil) != hasSOA || (soa != nil && soa.Type() != "SOA") {
			t.Errorf("Origin(%q): soa = %v", tc.text, soa)
		}
	}
}

func TestResolveOwners(t *testing.T) {
	f := &File{Entries: parseEntries(t, "$ORIGIN example.org.\n@ IN SOA a b 1 2 3 4 5\n IN NS ns\nwww IN A 192.0.2.1\n IN AAAA 2001:db8::1\nother.org. IN A 192.0.2.2\n$ORIGIN sub.example.org.\nhost IN A 192.0.2.3\n")}
	if err := f.ResolveOwners("example.org."); err != nil {
		t.Fatal(err)
	}
	var owners []string
	for _, e := range f.Records() {
		owners = append(owners, e.Owner())
	}
	if got, want := strings.Join(owners, " "), "@ @ www www other.org. host.sub"; got != want {
		t.Errorf("owners = %q, want %q", got, want)
	}
	g := &File{Entries: parseEntries(t, " IN A 192.0.2.1\nwww IN A 192.0.2.2\n")}
	if err := g.ResolveOwners("example.org."); err != nil || g.Entries[0].Owner() != "" || g.Entries[1].Owner() != "www" {
		t.Errorf("ownerless first record: %v %q", err, g.Entries[0].Owner())
	}
	h := &File{Entries: parseEntries(t, "@ IN A 192.0.2.1\n")}
	if err := h.ResolveOwners(""); err == nil {
		t.Error("@ without origin must fail")
	}
	// Stop the iterator early.
	n := 0
	for range f.Records() {
		n++
		break
	}
	if n != 1 {
		t.Error("Records iterator did not stop")
	}
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
		if got != tc.want || ok != tc.ok {
			t.Errorf("StringToTTL(%q) = %d, %v; want %d, %v", tc.in, got, ok, tc.want, tc.ok)
		}
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
		if got != tc.want {
			t.Errorf("Quote(%q) = %q, want %q", tc.in, got, tc.want)
		}
		f, err := Parse([]byte("t IN TXT " + got + "\n"))
		if err != nil || f.Entries[0].Values()[0] != tc.in {
			t.Errorf("Quote(%q) does not read back: %v", tc.in, err)
		}
	}
}

func TestEntryAccessors(t *testing.T) {
	es := parseEntries(t, "; top\n\n$TTL 1h ; default\nwww 300 IN TXT ( ; head\n \"a\" ; one\n \"b\" ) ; end\n")
	if len(es) != 4 || es[0].Kind() != Comment || es[1].Kind() != Blank || es[2].Kind() != Directive || es[3].Kind() != Record {
		t.Fatalf("kinds: %v", es)
	}
	if es[0].Comment() != "; top" || es[0].Line() != 1 || Kind(9).String() != "kind(9)" || Record.String() != "record" {
		t.Error("comment entry")
	}
	if d := es[2]; d.Name() != "$TTL" || d.Args()[0].Raw != "1h" || strings.Join(d.Comments(), ",") != "; default" || d.RawValues()[0] != "1h" || d.Line() != 3 {
		t.Errorf("directive entry: %+v", d)
	}
	r := es[3]
	ttl, ok := r.TTL()
	if r.Owner() != "www" || !ok || ttl.Seconds != 300 || ttl.Raw != "300" || r.Class() != "IN" || r.Type() != "TXT" || r.RType() != dns.TypeTXT || r.Line() != 4 {
		t.Errorf("record header: %+v", r)
	}
	if got := strings.Join(r.Comments(), ","); got != "; head,; one,; end" {
		t.Errorf("comments = %q", got)
	}
	if got := strings.Join(r.Head(), ","); got != "; head" {
		t.Errorf("head = %q", got)
	}
	if got := strings.Join(r.Tail(), ","); got != "; end" {
		t.Errorf("tail = %q", got)
	}
	fs := r.Fields()
	if len(fs) != 2 || !fs[0].Quoted || fs[0].Comments[0] != "; one" || fs[1].Comments != nil {
		t.Errorf("fields = %+v", fs)
	}
	fs[0].Comments[0] = "mutated"
	if r.Fields()[0].Comments[0] != "; one" {
		t.Error("Fields() must return a copy")
	}
	if r.Content() != "ab" || strings.Join(r.RawValues(), ",") != `"a","b"` || strings.Join(r.Values(), ",") != "a,b" {
		t.Error("values")
	}
	w := r.WithComments("note", "; two", " ")
	if got := strings.Join(w.Tail(), ","); got != "; end,; note ; two" {
		t.Errorf("WithComments tail = %q", got)
	}
	if strings.Join(r.Tail(), ",") != "; end" || r.WithComments().Equal(r) != true {
		t.Error("WithComments must not alias or change the original")
	}
	if es[0].WithComments("x").Comment() != "; top ; x" || es[1].WithComments("x").Comment() != "; x" || es[1].WithComments("x").Kind() != Comment {
		t.Error("WithComments on comment/blank")
	}
	if r.WithOwner("other").Owner() != "other" || r.Owner() != "www" || r.WithOwner("").Owner() != "" {
		t.Error("WithOwner")
	}
	var zero Entry
	if zero.Kind() != Blank || len(zero.Values()) != 0 || len(zero.Comments()) != 0 || zero.Content() != "" {
		t.Error("zero entry")
	}
	mx := parseEntries(t, "@ MX 10 mail\n")[0]
	if mx.Content() != "10 mail" || mx.Class() != "" || mx.classOrDefault() != "IN" {
		t.Error("MX content/class")
	}
}

func TestParseDetails(t *testing.T) {
	es := parseEntries(t, "a\tIN\tA\t192.0.2.1\r\n\r\n\r\n\n  ; indented\r\nb type65280 \\# 1 00\nc class3 TYPE1 x\nd 1H IN A x\ne IN 1h A x\n$include other.zone\n$GENERATE 1-10 h$ A 192.0.2.$ ; gen\n$origin foo ; o\n$TTL 1h\n\n\n")
	if len(es) != 12 {
		t.Fatalf("got %d entries: %+v", len(es), es)
	}
	if es[1].Kind() != Blank || es[2].Kind() != Comment || es[2].Comment() != "; indented" {
		t.Errorf("blank/comment: %+v", es[1:3])
	}
	if e := es[3]; e.Type() != "TYPE65280" || e.RType() != 65280 || e.Owner() != "b" || strings.Join(e.RawValues(), " ") != `\# 1 00` {
		t.Errorf("TYPE65280: %+v", e)
	}
	if e := es[4]; e.Class() != "CLASS3" || e.Type() != "TYPE1" || e.RType() != 1 {
		t.Errorf("class3/TYPE1: %+v", e)
	}
	if _, ok := es[5].TTL(); !ok || es[5].Class() != "IN" {
		t.Error("ttl before class")
	}
	if _, ok := es[6].TTL(); !ok || es[6].Class() != "IN" {
		t.Error("class before ttl")
	}
	if es[7].Name() != "$INCLUDE" || es[8].Name() != "$GENERATE" || strings.Join(es[8].Tail(), "") != "; gen" || es[9].Name() != "$ORIGIN" || es[10].Name() != "$TTL" {
		t.Errorf("directives: %+v", es[7:])
	}
	if last := es[len(es)-1]; last.Kind() != Blank || last.Line() != 14 {
		t.Errorf("trailing blank lines must be kept as one entry: %+v", last)
	}
	// A final line without terminator.
	if es := parseEntries(t, "a IN A 1"); len(es) != 1 || es[0].Owner() != "a" {
		t.Error("no final newline")
	}
	// Empty input.
	if es := parseEntries(t, ""); len(es) != 0 {
		t.Error("empty input")
	}
	// Comments in every position of a multi-line record.
	es = parseEntries(t, "a IN TXT ( ; h1\n ; h2\n \"x\" ; fx\n ; fx2\n \"y\" ) ; t\n")
	e := es[0]
	if strings.Join(e.Head(), ",") != "; h1,; h2" || strings.Join(e.Fields()[0].Comments, ",") != "; fx,; fx2" || strings.Join(e.Tail(), ",") != "; t" {
		t.Errorf("comment positions: %+v", e)
	}
	// Zero-field record with a comment keeps it as tail.
	e = parseEntries(t, "a IN A ; none\n")[0]
	if len(e.Head()) != 0 || strings.Join(e.Tail(), "") != "; none" {
		t.Errorf("zero-field comment: %+v", e)
	}
	// Escapes in items.
	e = parseEntries(t, `a\;b\ c IN TXT d\\e\032`+"\n")[0]
	if e.Owner() != `a\;b\ c` || e.Values()[0] != `d\e ` || e.RawValues()[0] != `d\\e\032` {
		t.Errorf("item escapes: %+v", e)
	}
	// Blank-led line without previous owner still parses.
	e = parseEntries(t, "  IN A 192.0.2.1\n")[0]
	if e.Owner() != "" || e.Type() != "A" {
		t.Errorf("inherited owner: %+v", e)
	}
	// Opaque high bytes are kept.
	e = parseEntries(t, "xn--\xc3\xa9 IN TXT \"\xff\"\n")[0]
	if e.Owner() != "xn--\xc3\xa9" || e.Values()[0] != "\xff" {
		t.Errorf("high bytes: %+v", e)
	}
	// Parse error line numbers.
	_, err := Parse([]byte("a IN A 1\nb IN A 2\n$NOPE\n"))
	var pe *ParseError
	if !errors.As(err, &pe) || pe.Line != 3 || pe.Col != 1 || pe.Error() != "line 3: unknown directive $NOPE" {
		t.Errorf("error = %v", err)
	}
	_, err = Parse([]byte("a IN A 1 ; c\n IN"))
	if !errors.As(err, &pe) || pe.Line != 2 || pe.Msg != "missing type" {
		t.Errorf("error = %v", err)
	}
}
