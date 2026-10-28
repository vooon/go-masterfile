// SPDX-License-Identifier: Apache-2.0

package masterfile

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestFormatCases(t *testing.T) {
	for _, tc := range []struct{ name, in, want string }{
		{"long owner overflows the column",
			"$ORIGIN e.\na IN A 1\nabcdefghijklmnopqrstuvwxyz0123456789.example.org. IN A 2\n",
			"$ORIGIN e.\na                        IN A 1\nabcdefghijklmnopqrstuvwxyz0123456789.example.org. IN A 2\n"},
		{"comment between same owners repeats the owner",
			"$ORIGIN e.\na IN A 1\n; c\na IN A 2\n\na IN A 3\n$TTL 1h\na IN A 4\n IN A 5\n",
			"$ORIGIN e.\na IN A 1\n; c\na IN A 2\n\na IN A 3\n$TTL 1h\na IN A 4\n  IN A 5\n"},
		{"origin changes the displayed owner",
			"$ORIGIN e.\n@ IN A 1\n$ORIGIN sub.e.\n@ IN A 2\ne. IN A 3\nx IN A 4\n$ORIGIN e.\nx.sub IN A 5\n",
			"$ORIGIN e.\n@     IN A 1\n$ORIGIN sub.e.\n@     IN A 2\ne.    IN A 3\nx     IN A 4\n$ORIGIN e.\nx.sub IN A 5\n"},
		{"origin argument made absolute and directive comments kept",
			"$ORIGIN e ; o\n$TTL 1h ; t\n$INCLUDE a b ; i\na IN A 1\n",
			"$ORIGIN e. ; o\n$TTL 1h ; t\n$INCLUDE a b ; i\na IN A 1\n"},
		{"ttl column with mixed units",
			"$ORIGIN e.\na 1h IN A 1\nb 30 IN A 2\n$TTL 1h\nc 3600 IN A 3\nd IN A 4\n",
			"$ORIGIN e.\na 3600 IN A 1\nb   30 IN A 2\n$TTL 1h\nc      IN A 3\nd      IN A 4\n"},
		{"txt requoted and single string stays one line",
			"$ORIGIN e.\na IN TXT hello\nb IN TXT \"a\\\"b\" ; c\nc IN SPF (\"x\")\n",
			"$ORIGIN e.\na IN TXT \"hello\"\nb IN TXT \"a\\\"b\" ; c\nc IN SPF \"x\"\n"},
		{"caa third field requoted",
			"$ORIGIN e.\n@ IN CAA 0 issue ca.example\n@ IN CAA 0 iodef \"mailto:a@b\"\n",
			"$ORIGIN e.\n@ IN CAA 0 issue \"ca.example\"\n  IN CAA 0 iodef \"mailto:a@b\"\n"},
		{"multi-line with comments aligned",
			"$ORIGIN e.\na IN TXT ( ; head\n \"x\" ; fx\n \"longer\" ; fl\n \"last\" ) ; t\n",
			"$ORIGIN e.\na IN TXT ( ; head\n    \"x\"      ; fx\n    \"longer\" ; fl\n    \"last\"   ; t\n)\n"},
		{"multi-line forced by a field comment on non-text type",
			"$ORIGIN e.\n@ IN MX ( 10 ; pref\n mail )\n",
			"$ORIGIN e.\n@ IN MX (\n    10 ; pref\n    mail\n)\n"},
		{"head comment only",
			"$ORIGIN e.\n@ IN MX ( ; h\n 10 mail )\n",
			"$ORIGIN e.\n@ IN MX ( ; h\n    10\n    mail\n)\n"},
		{"zero rdata keeps its comment",
			"$ORIGIN e.\n@ IN A ; nothing\n",
			"$ORIGIN e.\n@ IN A ; nothing\n"},
		{"soa with user comments and generated labels",
			"$ORIGIN e.\n@ IN SOA ( ; h\n ns ; m\n host ; r\n 2024010100 ; serial  Mon, 01 Jan 2024 #00 ; mine\n 1 ; refresh\n 2 ; my retry\n 3 4 ) ; end\n",
			"$ORIGIN e.\n@ IN SOA ns host ( ; h ; m ; r\n    2024010100 ; serial  Mon, 01 Jan 2024 #00 ; mine\n    1          ; refresh\n    2          ; my retry\n    3          ; expire\n    4          ; end\n)\n"},
		{"soa non-numeric serial",
			"$ORIGIN e.\n@ IN SOA ns host abc 1 2 3 4\n",
			"$ORIGIN e.\n@ IN SOA ns host (\n    abc ; serial\n    1   ; refresh\n    2   ; retry\n    3   ; expire\n    4   ; minimum\n)\n"},
		{"short dnskey stays on one line",
			"$ORIGIN e.\n@ IN DNSKEY 257 3 13 short ; c\n",
			"$ORIGIN e.\n@ IN DNSKEY 257 3 13 short ; c\n"},
		{"rrsig split keeps eight fields and all comments",
			"$ORIGIN e.\n@ IN RRSIG A 13 2 3600 ( ; h\n 20240101000000 20231201000000 12345 e. ; f\n AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB ) ; t\n",
			"$ORIGIN e.\n@ IN RRSIG A 13 2 3600 20240101000000 20231201000000 12345 e. ( ; h ; f ; t\n    AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n    AAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\n    BBBBBB\n)\n"},
		{"ds exactly 55 stays on one line",
			"$ORIGIN e.\n@ IN DS 1 2 3 " + strings.Repeat("a", 55) + "\n",
			"$ORIGIN e.\n@ IN DS 1 2 3 " + strings.Repeat("a", 55) + "\n"},
		{"leading and trailing blanks dropped, runs collapsed",
			"\n\n$ORIGIN e.\n\n\n; c\n\n\na IN A 1\n\n\n",
			"$ORIGIN e.\n\n; c\n\na IN A 1\n"},
		{"no origin keeps relative names",
			"www IN A 192.0.2.1\n IN A 192.0.2.2\nexample.org. IN MX 10 mx\n",
			"www         IN A  192.0.2.1\n            IN A  192.0.2.2\nexample.org IN MX 10 mx\n"},
		{"crlf input",
			"$ORIGIN e.\r\na IN A 1\r\n",
			"$ORIGIN e.\na IN A 1\n"},
		{"ownerless first record",
			"$ORIGIN e.\n IN A 1\nb IN A 2\n",
			"$ORIGIN e.\n  IN A 1\nb IN A 2\n"},
		{"class written as parsed",
			"$ORIGIN e.\na ch a 1\nb A 2\n",
			"$ORIGIN e.\na CH A 1\nb IN A 2\n"},
		{"empty input",
			"", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := reformat(t, tc.in, "", false)
			if got != tc.want {
				t.Errorf("got:\n%s\nwant:\n%s", got, tc.want)
			}
			if again := reformat(t, got, "", false); again != got {
				t.Errorf("not idempotent:\n%s\nvs:\n%s", got, again)
			}
		})
	}
}

func TestFormatHint(t *testing.T) {
	got := reformat(t, "@ IN SOA ns host 1 2 3 4 5\nwww IN A 1\n", "example.org", false)
	if !strings.HasPrefix(got, "@   IN SOA ns host (\n") || !strings.HasSuffix(got, "www IN A   1\n") {
		t.Errorf("got:\n%s", got)
	}
	got = reformat(t, "a IN A 1\n@ IN SOA ns host 1 2 3 4 5\n", "sub.example.org.", false)
	if !strings.HasPrefix(got, "a IN A   1\n@ IN SOA") {
		t.Errorf("got:\n%s", got)
	}
}

func TestFormatErrors(t *testing.T) {
	es := parseEntries(t, "@ IN SOA ns host 1 2 3\n")
	if err := Format(&bytes.Buffer{}, "e.", es, false); err == nil || !strings.Contains(err.Error(), "SOA has 5 fields") {
		t.Errorf("short SOA: %v", err)
	}
	if err := Reformat([]byte("@ IN SOA ns host 1 2 3 4 5 6\n"), "e.", &bytes.Buffer{}, false); err == nil {
		t.Error("long SOA via Reformat")
	}
	if err := Reformat([]byte(")"), "", &bytes.Buffer{}, false); err == nil {
		t.Error("parse error via Reformat")
	}
	if got := reformat(t, "@ IN A 192.0.2.1\n", "", false); got != "@ IN A 192.0.2.1\n" {
		t.Errorf("@ with the root fallback: %q", got)
	}
	want := errors.New("disk full")
	if err := Format(failWriter{want}, "e.", parseEntries(t, "a IN A 1\n"), false); !errors.Is(err, want) {
		t.Errorf("write error = %v", err)
	}
	if err := WritePlain(failWriter{want}, "e.", parseEntries(t, "a IN A 1\n")); !errors.Is(err, want) {
		t.Errorf("plain write error = %v", err)
	}
}

type failWriter struct{ err error }

func (f failWriter) Write([]byte) (int, error) { return 0, f.err }

func TestFormatBumpsFirstSOAOnly(t *testing.T) {
	withClock(t, 1700000000)
	got := reformat(t, "$ORIGIN e.\n@ IN SOA ns host 2024010100 1 2 3 4\nsub IN SOA ns host 2024010100 1 2 3 4\n", "", true)
	if strings.Count(got, "2024010101") != 1 || strings.Count(got, "2024010100") != 1 {
		t.Errorf("got:\n%s", got)
	}
}

func TestWritePlain(t *testing.T) {
	f, err := Parse([]byte("; c\n\n$ORIGIN e. ; o\n$TTL 1h\n@ 1h IN SOA ns host ( 1 ; s\n 2 3 4 5 )\nwww IN TXT a \"b c\" ; t\n IN A 192.0.2.1\n$ORIGIN sub.e.\nx IN A 192.0.2.2\ne. IN A 192.0.2.3\n IN AAAA 2001:db8::1\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.ResolveOwners("e."); err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	if err := WritePlain(&b, "e.", f.Entries); err != nil {
		t.Fatal(err)
	}
	want := "; c\n\n$ORIGIN e. ; o\n$TTL 1h\n@ 1h IN SOA (\n    ns\n    host\n    1 ; s\n    2\n    3\n    4\n    5\n)\nwww IN TXT a \"b c\" ; t\nwww IN A 192.0.2.1\n$ORIGIN sub.e.\nx IN A 192.0.2.2\ne. IN A 192.0.2.3\ne. IN AAAA 2001:db8::1\n"
	if b.String() != want {
		t.Errorf("got:\n%s\nwant:\n%s", b.String(), want)
	}
	var out bytes.Buffer
	if err := Format(&out, "e.", f.Entries, false); err != nil {
		t.Fatal(err)
	}
	if err := Verify("e.", b.Bytes(), out.Bytes()); err != nil {
		t.Errorf("Verify: %v\n%s", err, out.String())
	}
}

func TestVerify(t *testing.T) {
	plain := []byte("$ORIGIN e.\n@ IN SOA ns host 1 2 3 4 5\nwww IN A 192.0.2.1 ; keep\nwww IN A 192.0.2.2\n")
	for _, tc := range []struct{ name, formatted, msg string }{
		{"identical", string(plain), ""},
		{"serial ignored", "$ORIGIN e.\n@ IN SOA ns host 9 2 3 4 5\nwww IN A 192.0.2.1 ; serial  Mon, 01 Jan 2024 #00 ; keep\nwww IN A 192.0.2.2\n", ""},
		{"lost record", "$ORIGIN e.\n@ IN SOA ns host 1 2 3 4 5\nwww IN A 192.0.2.1 ; keep\n", "-www.e.\t0\tin\ta\t192.0.2.2"},
		{"added record", string(plain) + "x IN A 192.0.2.3\n", "+x.e.\t0\tin\ta\t192.0.2.3"},
		{"changed count", "$ORIGIN e.\n@ IN SOA ns host 1 2 3 4 5\nwww IN A 192.0.2.1 ; keep\nwww IN A 192.0.2.1\n", "records differ"},
		{"lost comment", "$ORIGIN e.\n@ IN SOA ns host 1 2 3 4 5\nwww IN A 192.0.2.1\nwww IN A 192.0.2.2\n", "comment lost: ; keep"},
		{"formatted does not parse", "$ORIGIN e.\n@ IN SOA ns host 1 2 3 4 5\nwww IN A nope\n", "formatted text does not parse"},
		{"formatted fails our parser", "$ORIGIN e.\n@ IN SOA ns host 1 2 3 4 5\nwww IN A 192.0.2.1 ; keep\nwww IN A 192.0.2.2\n$BOGUS\n", "formatted text"},
	} {
		err := Verify("e.", plain, []byte(tc.formatted))
		if tc.msg == "" {
			if err != nil {
				t.Errorf("%s: %v", tc.name, err)
			}
			continue
		}
		if !errors.Is(err, ErrUnsafeWrite) || !strings.Contains(err.Error(), tc.msg) {
			t.Errorf("%s: err = %v, want containing %q", tc.name, err, tc.msg)
		}
	}
	if err := Verify("e.", []byte("www IN A nope\n"), plain); !errors.Is(err, ErrUnsafeWrite) {
		t.Errorf("bad plain: %v", err)
	}
	if err := Verify("e.", []byte("$BOGUS\n"), []byte("")); !errors.Is(err, ErrUnsafeWrite) || !strings.Contains(err.Error(), "plain text") {
		t.Errorf("plain fails our parser: %v", err)
	}
	if _, err := Records("", []byte("$INCLUDE other\n")); err == nil {
		t.Error("$INCLUDE must be rejected")
	}
	if _, err := Comments([]byte(")")); err == nil {
		t.Error("Comments must report parse errors")
	}
	recs, err := Records("", []byte("www. IN A 192.0.2.1\nwww. IN A 192.0.2.1\n"))
	if err != nil || recs["www.\t0\tin\ta\t192.0.2.1"] != 2 {
		t.Errorf("Records = %v, %v", recs, err)
	}
}
