// SPDX-License-Identifier: Apache-2.0

package masterfile

import (
	"bytes"
	"fmt"
	"math/rand/v2"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
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
		f, err := Parse([]byte(text), "")
		require.NoError(t, err, "#%d Parse\n%s", i, text)
		apex := f.Apex()
		var formatted, reformatted, plain, again bytes.Buffer
		require.NoError(t, f.Format(&formatted, false), "#%d Format\n%s", i, text)
		require.NoError(t, Reformat([]byte(text), "", &reformatted, false), "#%d Reformat\n%s", i, text)
		require.Equal(t, formatted.String(), reformatted.String(), "#%d Reformat differs from Format", i)
		require.NoError(t, Reformat(formatted.Bytes(), "", &again, false), "#%d Reformat of output\n%s", i, formatted.String())
		require.Equal(t, formatted.String(), again.String(), "#%d not idempotent", i)
		require.NoError(t, f.WritePlain(&plain), "#%d WritePlain\n%s", i, text)
		require.NoError(t, Verify(apex, plain.Bytes(), formatted.Bytes()),
			"#%d Verify\n--- input ---\n%s--- plain ---\n%s--- formatted ---\n%s", i, text, plain.String(), formatted.String())
		// The formatted file parses to entries equal in meaning.
		g, err := Parse(formatted.Bytes(), "") // same hint as the first pass
		require.NoError(t, err, "#%d Parse of formatted\n%s", i, formatted.String())
		var ra, rb []Entry
		for _, e := range f.Records() {
			ra = append(ra, e)
		}
		for _, e := range g.Records() {
			rb = append(rb, e)
		}
		require.Len(t, rb, len(ra), "#%d record count", i)
		for j := range ra {
			require.True(t, ra[j].sameRecord(rb[j]), "#%d record %d differs: %+v vs %+v", i, j, ra[j], rb[j])
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
			require.ErrorIs(t, err, ErrInvalidRecord, "NewRecord(%q)", rdata)
			continue
		}
		var plain bytes.Buffer
		require.NoError(t, writePlain(&plain, "example.org.", "example.org.", []Entry{e}), "NewRecord(%q)", rdata)
		f, err := Parse(plain.Bytes(), "")
		require.NoError(t, err, "NewRecord(%q) wrote unparseable %q", rdata, plain.String())
		require.Len(t, f.Entries, 1, "NewRecord(%q) wrote %q which reads back as %+v", rdata, plain.String(), f.Entries)
		require.Equal(t, Record, f.Entries[0].Kind(), "NewRecord(%q) wrote %q which reads back as %+v", rdata, plain.String(), f.Entries)
		require.True(t, f.Entries[0].Equal(e), "NewRecord(%q) wrote %q which reads back as %+v", rdata, plain.String(), f.Entries)
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
		`$ORIGIN example.org.
$TTL 1h
@ IN SOA ns host ( 2024090101 ; s
 2h 30m 2w 1h )
www 300 IN A 192.0.2.1 ; c
 IN TXT ( "a" "b" )
`,
		`a IN TXT "\065\""
; c

$INCLUDE x
`,
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
		zf, err := Parse(data, "")
		if err != nil {
			var pe *ParseError
			require.ErrorAs(t, err, &pe, "non-ParseError")
			return
		}
		apex := zf.Apex()
		var plain, formatted bytes.Buffer
		require.NoError(t, zf.WritePlain(&plain), "WritePlain\n%q", data)
		if err := zf.Format(&formatted, false); err != nil {
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
		require.NoError(t, Verify(apex, plain.Bytes(), formatted.Bytes()),
			"Verify\n--- input ---\n%q\n--- plain ---\n%s--- formatted ---\n%s", data, plain.String(), formatted.String())
		var again bytes.Buffer
		require.NoError(t, Reformat(formatted.Bytes(), "", &again, false), "Reformat of output\n%s", formatted.String())
		require.Equal(t, formatted.String(), again.String(), "not idempotent")
	})
}

func newRand(a, b uint64) *rand.Rand { return rand.New(rand.NewPCG(a, b)) }
