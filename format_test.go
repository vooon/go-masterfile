// SPDX-License-Identifier: Apache-2.0

package masterfile

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFormatCases(t *testing.T) {
	for _, tc := range []struct{ name, in, want string }{
		{"long owner overflows the column",
			`$ORIGIN e.
a IN A 1
abcdefghijklmnopqrstuvwxyz0123456789.example.org. IN A 2
`,
			`$ORIGIN e.
a                        IN A 1
abcdefghijklmnopqrstuvwxyz0123456789.example.org. IN A 2
`},
		{"comment between same owners repeats the owner",
			`$ORIGIN e.
a IN A 1
; c
a IN A 2

a IN A 3
$TTL 1h
a IN A 4
 IN A 5
`,
			`$ORIGIN e.
a IN A 1
; c
a IN A 2

a IN A 3
$TTL 1h
a IN A 4
  IN A 5
`},
		{"origin changes the displayed owner",
			`$ORIGIN e.
@ IN A 1
$ORIGIN sub.e.
@ IN A 2
e. IN A 3
x IN A 4
$ORIGIN e.
x.sub IN A 5
`,
			`$ORIGIN e.
@     IN A 1
$ORIGIN sub.e.
@     IN A 2
e.    IN A 3
x     IN A 4
$ORIGIN e.
x.sub IN A 5
`},
		{"origin argument made absolute and directive comments kept",
			`$ORIGIN e ; o
$TTL 1h ; t
$INCLUDE a b ; i
a IN A 1
`,
			`$ORIGIN e. ; o
$TTL 1h ; t
$INCLUDE a b ; i
a IN A 1
`},
		{"ttl column with mixed units",
			`$ORIGIN e.
a 1h IN A 1
b 30 IN A 2
$TTL 1h
c 3600 IN A 3
d IN A 4
`,
			`$ORIGIN e.
a 3600 IN A 1
b   30 IN A 2
$TTL 1h
c      IN A 3
d      IN A 4
`},
		{"txt requoted and single string stays one line",
			`$ORIGIN e.
a IN TXT hello
b IN TXT "a\"b" ; c
c IN SPF ("x")
`,
			`$ORIGIN e.
a IN TXT "hello"
b IN TXT "a\"b" ; c
c IN SPF "x"
`},
		{"caa third field requoted",
			`$ORIGIN e.
@ IN CAA 0 issue ca.example
@ IN CAA 0 iodef "mailto:a@b"
`,
			`$ORIGIN e.
@ IN CAA 0 issue "ca.example"
  IN CAA 0 iodef "mailto:a@b"
`},
		{"multi-line with comments aligned",
			`$ORIGIN e.
a IN TXT ( ; head
 "x" ; fx
 "longer" ; fl
 "last" ) ; t
`,
			`$ORIGIN e.
a IN TXT ( ; head
    "x"      ; fx
    "longer" ; fl
    "last"   ; t
)
`},
		{"multi-line forced by a field comment on non-text type",
			`$ORIGIN e.
@ IN MX ( 10 ; pref
 mail )
`,
			`$ORIGIN e.
@ IN MX (
    10 ; pref
    mail
)
`},
		{"head comment only",
			`$ORIGIN e.
@ IN MX ( ; h
 10 mail )
`,
			`$ORIGIN e.
@ IN MX ( ; h
    10
    mail
)
`},
		{"zero rdata keeps its comment",
			`$ORIGIN e.
@ IN A ; nothing
`,
			`$ORIGIN e.
@ IN A ; nothing
`},
		{"soa with user comments and generated labels",
			`$ORIGIN e.
@ IN SOA ( ; h
 ns ; m
 host ; r
 2024010100 ; serial  Mon, 01 Jan 2024 #00 ; mine
 1 ; refresh
 2 ; my retry
 3 4 ) ; end
`,
			`$ORIGIN e.
@ IN SOA ns host ( ; h ; m ; r
    2024010100 ; serial  Mon, 01 Jan 2024 #00 ; mine
    1          ; refresh
    2          ; my retry
    3          ; expire
    4          ; end
)
`},
		{"soa non-numeric serial",
			`$ORIGIN e.
@ IN SOA ns host abc 1 2 3 4
`,
			`$ORIGIN e.
@ IN SOA ns host (
    abc ; serial
    1   ; refresh
    2   ; retry
    3   ; expire
    4   ; minimum
)
`},
		{"short dnskey stays on one line",
			`$ORIGIN e.
@ IN DNSKEY 257 3 13 short ; c
`,
			`$ORIGIN e.
@ IN DNSKEY 257 3 13 short ; c
`},
		{"rrsig split keeps eight fields and all comments",
			`$ORIGIN e.
@ IN RRSIG A 13 2 3600 ( ; h
 20240101000000 20231201000000 12345 e. ; f
 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB ) ; t
`,
			`$ORIGIN e.
@ IN RRSIG A 13 2 3600 20240101000000 20231201000000 12345 e. ( ; h ; f ; t
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    AAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
    BBBBBB
)
`},
		{"ds exactly 55 stays on one line",
			`$ORIGIN e.
@ IN DS 1 2 3 ` + strings.Repeat("a", 55) + "\n",
			`$ORIGIN e.
@ IN DS 1 2 3 ` + strings.Repeat("a", 55) + "\n"},
		{"leading and trailing blanks dropped, runs collapsed",
			`

$ORIGIN e.


; c


a IN A 1


`,
			`$ORIGIN e.

; c

a IN A 1
`},
		{"no origin keeps relative names",
			`www IN A 192.0.2.1
 IN A 192.0.2.2
example.org. IN MX 10 mx
`,
			`www         IN A  192.0.2.1
            IN A  192.0.2.2
example.org IN MX 10 mx
`},
		{"crlf input",
			"$ORIGIN e.\r\na IN A 1\r\n",
			`$ORIGIN e.
a IN A 1
`},
		{"ownerless first record",
			`$ORIGIN e.
 IN A 1
b IN A 2
`,
			`$ORIGIN e.
  IN A 1
b IN A 2
`},
		{"class written as parsed",
			`$ORIGIN e.
a ch a 1
b A 2
`,
			`$ORIGIN e.
a CH A 1
b IN A 2
`},
		{"empty input",
			"", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := reformat(t, tc.in, "", false)
			assert.Equal(t, tc.want, got)
			again := reformat(t, got, "", false)
			assert.Equal(t, got, again, "not idempotent")
		})
	}
}

func TestFormatHint(t *testing.T) {
	got := reformat(t, `@ IN SOA ns host 1 2 3 4 5
www IN A 1
`, "example.org", false)
	assert.True(t, strings.HasPrefix(got, "@   IN SOA ns host (\n"), "got:\n%s", got)
	assert.True(t, strings.HasSuffix(got, "www IN A   1\n"), "got:\n%s", got)
	got = reformat(t, `a IN A 1
@ IN SOA ns host 1 2 3 4 5
`, "sub.example.org.", false)
	assert.True(t, strings.HasPrefix(got, "a IN A   1\n@ IN SOA"), "got:\n%s", got)
}

func TestFormatErrors(t *testing.T) {
	short, err := Parse([]byte(`@ IN SOA ns host 1 2 3
`), "e.")
	require.NoError(t, err)
	err = short.Format(&bytes.Buffer{}, false)
	assert.ErrorContains(t, err, "SOA has 5 fields", "short SOA")
	short.Changed = true
	_, _, err = short.Commit(false)
	assert.ErrorContains(t, err, "SOA has 5 fields", "short SOA via Commit")
	err = Reformat([]byte(`@ IN SOA ns host 1 2 3 4 5 6
`), "e.", &bytes.Buffer{}, false)
	assert.Error(t, err, "long SOA via Reformat")
	err = Reformat([]byte(")"), "", &bytes.Buffer{}, false)
	assert.Error(t, err, "parse error via Reformat")
	got := reformat(t, `@ IN A 192.0.2.1
`, "", false)
	assert.Equal(t, `@ IN A 192.0.2.1
`, got, "@ with the root fallback")
	want := errors.New("disk full")
	z, err := Parse([]byte(`a IN A 1
`), "e.")
	require.NoError(t, err)
	err = z.Format(failWriter{want}, false)
	assert.ErrorIs(t, err, want, "Format write error")
	err = z.WritePlain(failWriter{want})
	assert.ErrorIs(t, err, want, "WritePlain write error")
	z.Changed = true
	_, _, err = z.Commit(false)
	assert.ErrorIs(t, err, ErrUnsafeWrite, "Commit of an unparseable record")
	err = Reformat([]byte(`$ORIGIN a.
@ IN SOA ns host 1 2 3 4 5
`), "b.", &bytes.Buffer{}, false)
	assert.ErrorIs(t, err, ErrApexMismatch, "Reformat with the wrong apex")
}

type failWriter struct{ err error }

func (f failWriter) Write([]byte) (int, error) { return 0, f.err }

func TestFormatBumpsFirstSOAOnly(t *testing.T) {
	withClock(t, 1700000000)
	got := reformat(t, `$ORIGIN e.
@ IN SOA ns host 2024010100 1 2 3 4
sub IN SOA ns host 2024010100 1 2 3 4
`, "", true)
	assert.Equal(t, 1, strings.Count(got, "2024010101"), "got:\n%s", got)
	assert.Equal(t, 1, strings.Count(got, "2024010100"), "got:\n%s", got)
}

func TestWritePlain(t *testing.T) {
	f, err := Parse([]byte(`; c

$ORIGIN e. ; o
$TTL 1h
@ 1h IN SOA ns host ( 1 ; s
 2 3 4 5 )
www IN TXT a "b c" ; t
 IN A 192.0.2.1
$ORIGIN sub.e.
x IN A 192.0.2.2
e. IN A 192.0.2.3
 IN AAAA 2001:db8::1
`), "")
	require.NoError(t, err)
	var b bytes.Buffer
	require.NoError(t, f.WritePlain(&b))
	want := `; c

$ORIGIN e. ; o
$TTL 1h
@ 1h IN SOA (
    ns
    host
    1 ; s
    2
    3
    4
    5
)
www IN TXT a "b c" ; t
www IN A 192.0.2.1
$ORIGIN sub.e.
x IN A 192.0.2.2
e. IN A 192.0.2.3
e. IN AAAA 2001:db8::1
`
	assert.Equal(t, want, b.String())
	var out bytes.Buffer
	require.NoError(t, f.Format(&out, false))
	assert.NoError(t, Verify("e.", b.Bytes(), out.Bytes()), "Verify:\n%s", out.String())
}

func TestVerify(t *testing.T) {
	plain := []byte(`$ORIGIN e.
@ IN SOA ns host 1 2 3 4 5
www IN A 192.0.2.1 ; keep
www IN A 192.0.2.2
`)
	for _, tc := range []struct{ name, formatted, msg string }{
		{"identical", string(plain), ""},
		{"serial ignored", `$ORIGIN e.
@ IN SOA ns host 9 2 3 4 5
www IN A 192.0.2.1 ; serial  Mon, 01 Jan 2024 #00 ; keep
www IN A 192.0.2.2
`, ""},
		{"lost record", `$ORIGIN e.
@ IN SOA ns host 1 2 3 4 5
www IN A 192.0.2.1 ; keep
`, "-www.e.\t0\tin\ta\t192.0.2.2"},
		{"added record", string(plain) + `x IN A 192.0.2.3
`, "+x.e.\t0\tin\ta\t192.0.2.3"},
		{"changed count", `$ORIGIN e.
@ IN SOA ns host 1 2 3 4 5
www IN A 192.0.2.1 ; keep
www IN A 192.0.2.1
`, "records differ"},
		{"lost comment", `$ORIGIN e.
@ IN SOA ns host 1 2 3 4 5
www IN A 192.0.2.1
www IN A 192.0.2.2
`, "comment lost: ; keep"},
		{"formatted does not parse", `$ORIGIN e.
@ IN SOA ns host 1 2 3 4 5
www IN A nope
`, "formatted text does not parse"},
		{"formatted fails our parser", `$ORIGIN e.
@ IN SOA ns host 1 2 3 4 5
www IN A 192.0.2.1 ; keep
www IN A 192.0.2.2
$BOGUS
`, "formatted text"},
	} {
		err := Verify("e.", plain, []byte(tc.formatted))
		if tc.msg == "" {
			assert.NoError(t, err, tc.name)
			continue
		}
		assert.ErrorIs(t, err, ErrUnsafeWrite, tc.name)
		assert.ErrorContains(t, err, tc.msg, tc.name)
	}
	err := Verify("e.", []byte(`www IN A nope
`), plain)
	assert.ErrorIs(t, err, ErrUnsafeWrite, "bad plain")
	err = Verify("e.", []byte(`$BOGUS
`), []byte(""))
	assert.ErrorIs(t, err, ErrUnsafeWrite, "plain fails our parser")
	assert.ErrorContains(t, err, "plain text", "plain fails our parser")
	_, err = Records("", []byte(`$INCLUDE other
`))
	assert.Error(t, err, "$INCLUDE must be rejected")
	_, err = Comments([]byte(")"))
	assert.Error(t, err, "Comments must report parse errors")
	recs, err := Records("", []byte(`www. IN A 192.0.2.1
www. IN A 192.0.2.1
`))
	assert.NoError(t, err)
	assert.Equal(t, 2, recs["www.\t0\tin\ta\t192.0.2.1"], "Records = %v", recs)
}
