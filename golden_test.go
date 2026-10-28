// SPDX-License-Identifier: Apache-2.0

package masterfile

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var update = flag.Bool("update", false, "regenerate testdata/*.golden files")

// TestGolden reformats every testdata/*.zone and compares it byte for byte
// with the matching .golden file (spec section 8.1 to 8.3 and more).
func TestGolden(t *testing.T) {
	zones, err := filepath.Glob("testdata/*.zone")
	require.NoError(t, err, "no testdata zones")
	require.NotEmpty(t, zones, "no testdata zones")
	for _, zone := range zones {
		name := strings.TrimSuffix(filepath.Base(zone), ".zone")
		t.Run(name, func(t *testing.T) {
			in, err := os.ReadFile(zone)
			require.NoError(t, err)
			var out bytes.Buffer
			require.NoError(t, Reformat(in, "", &out, false), "Reformat")
			golden := strings.TrimSuffix(zone, ".zone") + ".golden"
			if *update {
				require.NoError(t, os.WriteFile(golden, out.Bytes(), 0o644))
			}
			want, err := os.ReadFile(golden)
			require.NoError(t, err)
			assert.Equal(t, string(want), out.String(), "golden %s", golden)
			// Idempotence: formatting the output again reproduces it.
			var again bytes.Buffer
			require.NoError(t, Reformat(out.Bytes(), "", &again, false), "Reformat of output")
			assert.Equal(t, out.String(), again.String(), "not idempotent")
			// Safety: the formatted text verifies against the plain rendering.
			z, err := Parse(in, "")
			require.NoError(t, err)
			var plain bytes.Buffer
			require.NoError(t, z.WritePlain(&plain))
			assert.NoError(t, Verify(z.Apex(), plain.Bytes(), out.Bytes()), "Verify\n--- plain ---\n%s", plain.String())
		})
	}
}

func reformat(t *testing.T, in, hint string, bump bool) string {
	t.Helper()
	var out bytes.Buffer
	require.NoError(t, Reformat([]byte(in), hint, &out, bump), "Reformat(%q)", in)
	return out.String()
}

// Spec 8.4: Unix time serial rendering and bumping.
func TestUnixSerial(t *testing.T) {
	in := `$ORIGIN example.org.
@ IN SOA ns hostmaster 1282630067 4H 1H 7D 7200
`
	out := reformat(t, in, "", false)
	want := `    1282630067 ; serial  Tue, 24 Aug 2010 06:07:47 UTC
`
	assert.Contains(t, out, want, "got:\n%s", out)
	withClock(t, 1282630000) // clock not past the serial
	out = reformat(t, in, "", true)
	assert.Contains(t, out, `    1282630068 ; serial  Tue, 24 Aug 2010 06:07:48 UTC
`, "bump with old clock:\n%s", out)
	withClock(t, 1700000000)
	out = reformat(t, in, "", true)
	assert.Contains(t, out, `    1700000000 ; serial  Tue, 14 Nov 2023 22:13:20 UTC
`, "bump with new clock:\n%s", out)
}

func TestParseErrors(t *testing.T) {
	// Spec 8.8.
	for _, in := range []string{
		"a IN TXT \"unterminated",
		"a IN TXT \"ends with backslash\\",
		"@ IN SOA a b (1 2 3 4 5",
		")",
		"$ORIGIN",
		"$TTL\n",
		"a IN NS b\x00c",
		"a IN A 1\rb IN A 2\n",
		`a IN A 1 ; c
 IN`,
		"a 1 2 IN A x",
		"a IN IN A x",
		"\xEF\xBB\xBFa IN A 192.0.2.1",
		"a IN A ( 1 ( 2 ) )",
		"$FOO bar",
		"$TTL nope",
		"a IN \"A\" x",
		"a IN NOPE x",
		"a IN TXT b\\",
	} {
		_, err := Parse([]byte(in), "")
		var pe *ParseError
		if !assert.ErrorAs(t, err, &pe, "Parse(%q)", in) {
			continue
		}
		assert.GreaterOrEqual(t, pe.Line, 1, "Parse(%q) error %q lacks a line", in, pe)
		assert.True(t, strings.HasPrefix(pe.Error(), "line "), "Parse(%q) error %q lacks a line", in, pe)
	}
	f, err := Parse([]byte(`a IN TXT "\1x" "\999" "\0650"`), "")
	require.NoError(t, err)
	assert.Equal(t, []string{"1x", "999", "A0"}, f.Entries[0].Values(), "escapes")
}
