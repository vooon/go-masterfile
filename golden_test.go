// SPDX-License-Identifier: Apache-2.0

package masterfile

import (
	"bytes"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "regenerate testdata/*.golden files")

// TestGolden reformats every testdata/*.zone and compares it byte for byte
// with the matching .golden file (spec section 8.1 to 8.3 and more).
func TestGolden(t *testing.T) {
	zones, err := filepath.Glob("testdata/*.zone")
	if err != nil || len(zones) == 0 {
		t.Fatalf("no testdata zones: %v", err)
	}
	for _, zone := range zones {
		name := strings.TrimSuffix(filepath.Base(zone), ".zone")
		t.Run(name, func(t *testing.T) {
			in, err := os.ReadFile(zone)
			if err != nil {
				t.Fatal(err)
			}
			var out bytes.Buffer
			if err := Reformat(in, "", &out, false); err != nil {
				t.Fatalf("Reformat: %v", err)
			}
			golden := strings.TrimSuffix(zone, ".zone") + ".golden"
			if *update {
				if err := os.WriteFile(golden, out.Bytes(), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(golden)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(out.Bytes(), want) {
				t.Errorf("output differs from %s:\n--- got ---\n%s--- want ---\n%s", golden, out.Bytes(), want)
			}
			// Idempotence: formatting the output again reproduces it.
			var again bytes.Buffer
			if err := Reformat(out.Bytes(), "", &again, false); err != nil {
				t.Fatalf("Reformat of output: %v", err)
			}
			if !bytes.Equal(again.Bytes(), out.Bytes()) {
				t.Errorf("not idempotent:\n--- first ---\n%s--- second ---\n%s", out.Bytes(), again.Bytes())
			}
			// Safety: the formatted text verifies against the plain rendering.
			f, err := Parse(in)
			if err != nil {
				t.Fatal(err)
			}
			apex, _ := f.Origin("")
			if apex == "" {
				apex = "."
			}
			if err := f.ResolveOwners(apex); err != nil {
				t.Fatal(err)
			}
			var plain bytes.Buffer
			if err := WritePlain(&plain, apex, f.Entries); err != nil {
				t.Fatal(err)
			}
			if err := Verify(apex, plain.Bytes(), out.Bytes()); err != nil {
				t.Errorf("Verify: %v\n--- plain ---\n%s", err, plain.Bytes())
			}
		})
	}
}

func reformat(t *testing.T, in, hint string, bump bool) string {
	t.Helper()
	var out bytes.Buffer
	if err := Reformat([]byte(in), hint, &out, bump); err != nil {
		t.Fatalf("Reformat(%q): %v", in, err)
	}
	return out.String()
}

// Spec 8.4: Unix time serial rendering and bumping.
func TestUnixSerial(t *testing.T) {
	in := "$ORIGIN example.org.\n@ IN SOA ns hostmaster 1282630067 4H 1H 7D 7200\n"
	out := reformat(t, in, "", false)
	want := "    1282630067 ; serial  Tue, 24 Aug 2010 06:07:47 UTC\n"
	if !strings.Contains(out, want) {
		t.Errorf("got:\n%s\nwant line %q", out, want)
	}
	withClock(t, 1282630000) // clock not past the serial
	if out := reformat(t, in, "", true); !strings.Contains(out, "    1282630068 ; serial  Tue, 24 Aug 2010 06:07:48 UTC\n") {
		t.Errorf("bump with old clock:\n%s", out)
	}
	withClock(t, 1700000000)
	if out := reformat(t, in, "", true); !strings.Contains(out, "    1700000000 ; serial  Tue, 14 Nov 2023 22:13:20 UTC\n") {
		t.Errorf("bump with new clock:\n%s", out)
	}
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
		"a IN A 1 ; c\n IN",
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
		_, err := Parse([]byte(in))
		var pe *ParseError
		if !errors.As(err, &pe) {
			t.Errorf("Parse(%q) = %v, want *ParseError", in, err)
			continue
		}
		if pe.Line < 1 || !strings.HasPrefix(pe.Error(), "line ") {
			t.Errorf("Parse(%q) error %q lacks a line", in, pe)
		}
	}
	f, err := Parse([]byte(`a IN TXT "\1x" "\999" "\0650"`))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := f.Entries[0].Values(), []string{"1x", "999", "A0"}; strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("escapes: got %q, want %q", got, want)
	}
}
