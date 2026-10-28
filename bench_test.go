// SPDX-License-Identifier: Apache-2.0

package masterfile

import (
	"bytes"
	"math/rand/v2"
	"strings"
	"testing"
)

// benchZone is a 1000-record zone built from the property generator.
func benchZone(tb testing.TB) []byte {
	tb.Helper()
	r := rand.New(rand.NewPCG(7, 8))
	var b strings.Builder
	for b.Len() < 64<<10 {
		b.WriteString(genZone(r))
	}
	return []byte(b.String())
}

func BenchmarkParse(b *testing.B) {
	data := benchZone(b)
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	for b.Loop() {
		if _, err := Parse(data, "example.org."); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkFormat(b *testing.B) {
	z, err := Parse(benchZone(b), "example.org.")
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		var out bytes.Buffer
		if err := z.Format(&out, false); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCommit(b *testing.B) {
	z, err := Parse(benchZone(b), "example.org.")
	if err != nil {
		b.Fatal(err)
	}
	z.Changed = true
	b.ReportAllocs()
	for b.Loop() {
		if _, _, err := z.Commit(false); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkApplyReplace(b *testing.B) {
	z, err := Parse(benchZone(b), "example.org.")
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		w := *z
		if _, err := w.Apply(Replace{
			Selector: Selector{Owner: "www", Types: []uint16{1}, Contents: []string{"192.0.2.1", "192.0.2.2"}},
			Records:  []RR{{Type: 1, Content: "198.51.100.1"}},
		}); err != nil {
			b.Fatal(err)
		}
	}
}
