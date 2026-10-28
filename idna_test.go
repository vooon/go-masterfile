// SPDX-License-Identifier: Apache-2.0

package masterfile

import (
	"bytes"
	"errors"
	"testing"
)

func TestToASCII(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"", ""},
		{"@", "@"},
		{"*", "*"},
		{".", "."},
		{"www.example.org.", "www.example.org."},
		{"WWW.Example.ORG", "WWW.Example.ORG"},
		{"_acme-challenge.example.org.", "_acme-challenge.example.org."},
		{"bücher", "xn--bcher-kva"},
		{"bücher.example.org.", "xn--bcher-kva.example.org."},
		{"WWW.Bücher.example.", "WWW.xn--bcher-kva.example."},
		{"*.bücher", "*.xn--bcher-kva"},
		{"_dmarc.bücher.", "_dmarc.xn--bcher-kva."},
		{"пример.рф.", "xn--e1afmkfd.xn--p1ai."},
		{"xn--bcher-kva.example.", "xn--bcher-kva.example."},
		{`a\.b.example.`, `a\.b.example.`},
		{`a\ b.example.`, `a\ b.example.`},
		{"bücher..example.", "xn--bcher-kva..example."},
	} {
		got, err := ToASCII(tc.in)
		if err != nil || got != tc.want {
			t.Errorf("ToASCII(%q) = %q, %v; want %q", tc.in, got, err, tc.want)
		}
	}
	for _, in := range []string{`bü\.cher`, "b\xffcher"} {
		if _, err := ToASCII(in); !errors.Is(err, ErrInvalidName) {
			t.Errorf("ToASCII(%q) = %v, want ErrInvalidName", in, err)
		}
	}
}

func TestToUnicode(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"", ""},
		{"@", "@"},
		{"www.example.org.", "www.example.org."},
		{"xn--bcher-kva.example.org.", "bücher.example.org."},
		{"XN--BCHER-KVA.Example.", "bücher.Example."},
		{"*.xn--bcher-kva", "*.bücher"},
		{"xn--e1afmkfd.xn--p1ai.", "пример.рф."},
		{"xn--zzz-999999999.example.", "xn--zzz-999999999.example."}, // undecodable: unchanged
		{`a\.b.xn--bcher-kva.`, `a\.b.bücher.`},
		{"bücher.example.", "bücher.example."},
	} {
		if got := ToUnicode(tc.in); got != tc.want {
			t.Errorf("ToUnicode(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// A Unicode owner converted with ToASCII goes through NewRecord, Format and
// Verify, and comes back out of ToUnicode.
func TestIDNARoundTrip(t *testing.T) {
	owner, err := ToASCII("Bücher")
	if err != nil {
		t.Fatal(err)
	}
	rec, err := NewRecord(owner, 0, 1, "192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	f, err := Parse([]byte("$ORIGIN example.org.\n@ IN SOA ns host 1 2 3 4 5\n"))
	if err != nil {
		t.Fatal(err)
	}
	f.Entries = append(f.Entries, rec)
	var plain, out bytes.Buffer
	if err := WritePlain(&plain, "example.org.", f.Entries); err != nil {
		t.Fatal(err)
	}
	if err := Format(&out, "example.org.", f.Entries, false); err != nil {
		t.Fatal(err)
	}
	if err := Verify("example.org.", plain.Bytes(), out.Bytes()); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(out.Bytes(), []byte("xn--bcher-kva IN A   192.0.2.1\n")) {
		t.Errorf("formatted:\n%s", out.String())
	}
	g, err := Parse(out.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	var last Entry
	for _, e := range g.Records() {
		last = e
	}
	if got := ToUnicode(last.Owner()); got != "bücher" {
		t.Errorf("ToUnicode(%q) = %q", last.Owner(), got)
	}
}
