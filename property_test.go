// SPDX-License-Identifier: Apache-2.0

package masterfile

import (
	"bytes"
	"errors"
	"fmt"
	"math/rand/v2"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// genZone builds a random but valid zone file from a fixed vocabulary.
func genZone(r *rand.Rand) string {
	pick := func(xs ...string) string { return xs[r.IntN(len(xs))] }
	var b strings.Builder
	b.WriteString("$ORIGIN example.org.\n")
	if r.IntN(2) == 0 {
		b.WriteString("$TTL " + pick("1h", "300", "1d") + "\n")
	}
	fmt.Fprintf(&b, "@ IN SOA ns1 hostmaster %s 2h 30m 2w 1h%s\n", pick("2024090101", "1282630067", "1"), pick("", " ; soa"))
	for range r.IntN(12) {
		owner := pick("@", "www", "mail", "WWW", "a.b", "other.org.", "")
		ttl := pick("", "", "300", "1h", "3600 ")
		if owner == "" {
			b.WriteString(" ")
		} else {
			b.WriteString(owner + " ")
		}
		if ttl != "" {
			b.WriteString(ttl + " ")
		}
		switch r.IntN(6) {
		case 0:
			b.WriteString("IN A 192.0.2." + fmt.Sprint(r.IntN(255)))
		case 1:
			b.WriteString("AAAA 2001:db8::" + fmt.Sprint(r.IntN(255)))
		case 2:
			b.WriteString("IN MX " + pick("10", "20") + " mail")
		case 3:
			b.WriteString("IN TXT " + pick(`"v=spf1 -all"`, `"a" "b"`, `( "x" ; c1`+"\n"+` "y" )`, `plain`))
		case 4:
			b.WriteString("IN CAA 0 issue " + pick(`"ca.example"`, `ca.example`))
		case 5:
			b.WriteString("IN NS " + pick("ns1", "ns2.example.net."))
		}
		b.WriteString(pick("", "", " ; note", " ; another"))
		b.WriteString(pick("\n", "\n", "\n\n", "\n; between\n"))
		if r.IntN(10) == 0 {
			b.WriteString("$ORIGIN " + pick("sub.example.org.", "example.org.", "other.org.") + "\n")
		}
		if r.IntN(10) == 0 {
			b.WriteString("$TTL " + pick("1h", "60") + "\n")
		}
	}
	return b.String()
}

func TestProperties(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	for i := range 300 {
		text := genZone(r)
		f, err := Parse([]byte(text))
		if err != nil {
			t.Fatalf("#%d Parse: %v\n%s", i, err, text)
		}
		apex, _ := f.Origin("")
		if err := f.ResolveOwners(apex); err != nil {
			t.Fatalf("#%d ResolveOwners: %v\n%s", i, err, text)
		}
		var formatted, reformatted, plain, again bytes.Buffer
		if err := Format(&formatted, apex, f.Entries, false); err != nil {
			t.Fatalf("#%d Format: %v\n%s", i, err, text)
		}
		if err := Reformat([]byte(text), "", &reformatted, false); err != nil {
			t.Fatalf("#%d Reformat: %v\n%s", i, err, text)
		}
		if !bytes.Equal(formatted.Bytes(), reformatted.Bytes()) {
			t.Fatalf("#%d Reformat differs from Format:\n%s\n---\n%s", i, formatted.Bytes(), reformatted.Bytes())
		}
		if err := Reformat(formatted.Bytes(), "", &again, false); err != nil || !bytes.Equal(again.Bytes(), formatted.Bytes()) {
			t.Fatalf("#%d not idempotent (%v):\n%s\n---\n%s", i, err, formatted.Bytes(), again.Bytes())
		}
		if err := WritePlain(&plain, apex, f.Entries); err != nil {
			t.Fatal(err)
		}
		if err := Verify(apex, plain.Bytes(), formatted.Bytes()); err != nil {
			t.Fatalf("#%d Verify: %v\n--- input ---\n%s--- plain ---\n%s--- formatted ---\n%s", i, err, text, plain.Bytes(), formatted.Bytes())
		}
		// The formatted file parses to entries equal in meaning.
		g, err := Parse(formatted.Bytes())
		if err != nil {
			t.Fatal(err)
		}
		if err := g.ResolveOwners(apex); err != nil {
			t.Fatal(err)
		}
		var ra, rb []Entry
		for _, e := range f.Records() {
			ra = append(ra, e)
		}
		for _, e := range g.Records() {
			rb = append(rb, e)
		}
		if len(ra) != len(rb) {
			t.Fatalf("#%d record count %d vs %d", i, len(ra), len(rb))
		}
		for j := range ra {
			if !ra[j].sameRecord(rb[j]) {
				t.Fatalf("#%d record %d differs: %+v vs %+v", i, j, ra[j], rb[j])
			}
		}
	}
}

func TestNewRecordProperty(t *testing.T) {
	r := rand.New(rand.NewPCG(3, 4))
	alphabet := []byte("abc \";()\\\n\t\x00\xff$@._-0123456789")
	for range 2000 {
		n := r.IntN(12)
		buf := make([]byte, n)
		for i := range buf {
			buf[i] = alphabet[r.IntN(len(alphabet))]
		}
		rdata := string(buf)
		owner := []string{"www", "@", "a.b", "x\\ y"}[r.IntN(4)]
		rtype := []uint16{dns.TypeA, dns.TypeTXT, dns.TypeMX, dns.TypeCAA}[r.IntN(4)]
		e, err := NewRecord(owner, uint32(r.IntN(2))*300, rtype, rdata)
		if err != nil {
			if !errors.Is(err, ErrInvalidRecord) {
				t.Fatalf("NewRecord(%q): %v", rdata, err)
			}
			continue
		}
		var plain bytes.Buffer
		if err := WritePlain(&plain, "example.org.", []Entry{e}); err != nil {
			t.Fatal(err)
		}
		f, err := Parse(plain.Bytes())
		if err != nil {
			t.Fatalf("NewRecord(%q) wrote unparseable %q: %v", rdata, plain.String(), err)
		}
		if len(f.Entries) != 1 || f.Entries[0].Kind() != Record || !f.Entries[0].Equal(e) {
			t.Fatalf("NewRecord(%q) wrote %q which reads back as %+v", rdata, plain.String(), f.Entries)
		}
	}
}

// hasOverflowEscape reports whether data contains a backslash followed by
// three digits whose value exceeds 255 (approximately: escaped backslashes
// are not accounted for, which only skips more inputs).
func hasOverflowEscape(data []byte) bool {
	for i := 0; i+3 < len(data); i++ {
		if data[i] == '\\' && isDigit(data[i+1]) && isDigit(data[i+2]) && isDigit(data[i+3]) {
			if _, n := decodeEscape(data[i:]); n == 2 {
				return true
			}
		}
	}
	return false
}

// hasBareTypeNameLine reports whether an indented continuation line of
// formatted starts with a token that is an RR type name.
func hasBareTypeNameLine(formatted []byte) bool {
	for line := range bytes.Lines(formatted) {
		rest, ok := bytes.CutPrefix(line, []byte(indent))
		if !ok {
			continue
		}
		tok, _, _ := bytes.Cut(rest, []byte(" "))
		if _, isType := typeNames[strings.ToUpper(strings.TrimSpace(string(tok)))]; isType {
			return true
		}
	}
	return false
}

func FuzzParse(f *testing.F) {
	for _, seed := range []string{
		"$ORIGIN example.org.\n$TTL 1h\n@ IN SOA ns host ( 2024090101 ; s\n 2h 30m 2w 1h )\nwww 300 IN A 192.0.2.1 ; c\n IN TXT ( \"a\" \"b\" )\n",
		"a IN TXT \"\\065\\\"\"\n; c\n\n$INCLUDE x\n",
		"@ IN DNSKEY 257 3 13 " + strings.Repeat("A", 120) + "\n",
		")\n", "(\n", "\"", "\xEF\xBB\xBF", "a\rb", "a IN A 1\x00",
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if hasOverflowEscape(data) {
			// "\DDD" above 255 is decoded differently by the reference
			// parser (it wraps the byte) and by this package (the backslash
			// escapes only the first digit, spec 8.8). Verify then rightly
			// refuses the write; there is no invariant to check.
			t.Skip("malformed \\DDD escape")
		}
		zf, err := Parse(data)
		if err != nil {
			var pe *ParseError
			if !errors.As(err, &pe) {
				t.Fatalf("non-ParseError %v", err)
			}
			return
		}
		apex, _ := zf.Origin("")
		if apex == "" {
			apex = "."
		}
		if err := zf.ResolveOwners(apex); err != nil {
			return
		}
		var plain, formatted bytes.Buffer
		if err := WritePlain(&plain, apex, zf.Entries); err != nil {
			t.Fatal(err)
		}
		if err := Format(&formatted, apex, zf.Entries, false); err != nil {
			return // only an SOA with the wrong field count
		}
		if _, err := Records(apex, plain.Bytes()); err != nil {
			return // the reference parser rejects it; nothing to prove
		}
		if hasBareTypeNameLine(formatted.Bytes()) {
			// miekg/dns resets its "type seen" state after a comment inside
			// parentheses, so a later bare field that spells a type name
			// (e.g. a key piece "A") is mis-tagged and the record rejected.
			// Verify then refuses the write; see docs/DESIGN.md.
			t.Skip("bare type-name field on its own line (reference parser quirk)")
		}
		if err := Verify(apex, plain.Bytes(), formatted.Bytes()); err != nil {
			t.Fatalf("%v\n--- input ---\n%q\n--- plain ---\n%s--- formatted ---\n%s", err, data, plain.Bytes(), formatted.Bytes())
		}
		var again bytes.Buffer
		if err := Reformat(formatted.Bytes(), apex, &again, false); err != nil || !bytes.Equal(again.Bytes(), formatted.Bytes()) {
			t.Fatalf("not idempotent (%v):\n%s\n---\n%s", err, formatted.Bytes(), again.Bytes())
		}
	})
}
