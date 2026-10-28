// SPDX-License-Identifier: Apache-2.0

package masterfile

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
		assert.NoError(t, err, "ToASCII(%q)", tc.in)
		assert.Equal(t, tc.want, got, "ToASCII(%q)", tc.in)
	}
	for _, in := range []string{`bü\.cher`, "b\xffcher"} {
		_, err := ToASCII(in)
		assert.ErrorIs(t, err, ErrInvalidName, "ToASCII(%q)", in)
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
		assert.Equal(t, tc.want, ToUnicode(tc.in), "ToUnicode(%q)", tc.in)
	}
}

// A Unicode owner converted with ToASCII goes through NewRecord, Format and
// Verify, and comes back out of ToUnicode.
func TestIDNARoundTrip(t *testing.T) {
	owner, err := ToASCII("Bücher")
	require.NoError(t, err)
	rec, err := NewRecord(owner, 0, 1, "192.0.2.1")
	require.NoError(t, err)
	f, err := Parse([]byte(`$ORIGIN example.org.
@ IN SOA ns host 1 2 3 4 5
`), "")
	require.NoError(t, err)
	f.Entries = append(f.Entries, rec)
	var plain, out bytes.Buffer
	require.NoError(t, f.WritePlain(&plain))
	require.NoError(t, f.Format(&out, false))
	require.NoError(t, Verify("example.org.", plain.Bytes(), out.Bytes()))
	assert.Contains(t, out.String(), `xn--bcher-kva IN A   192.0.2.1
`, "formatted:\n%s", out.String())
	g, err := Parse(out.Bytes(), "")
	require.NoError(t, err)
	var last Entry
	for _, e := range g.Records() {
		last = e
	}
	assert.Equal(t, "bücher", ToUnicode(last.Owner()), "ToUnicode(%q)", last.Owner())
}
