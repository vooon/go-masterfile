// SPDX-License-Identifier: Apache-2.0

package masterfile

import (
	"bufio"
	"io"
	"strings"
)

// writePlain implements [Zone.WritePlain] over resolved entries; origin is
// the origin in force before the first $ORIGIN line.
func writePlain(w io.Writer, origin, apex string, entries []Entry) error {
	bw := bufio.NewWriter(w)
	for _, e := range entries {
		switch e.kind {
		case Blank:
			bw.WriteByte('\n') //nolint:errcheck // sticky error reported by Flush
		case Comment:
			writeLine(bw, e.comment)
		case Directive:
			if e.name == "$ORIGIN" && len(e.args) > 0 {
				origin = Fqdn(e.args[0].Value)
			}
			writeLine(bw, directiveText(e))
		case Record:
			plainRecord(bw, origin, apex, e)
		}
	}
	return bw.Flush()
}

func writeLine(w *bufio.Writer, s string) {
	w.WriteString(s)  //nolint:errcheck // sticky error reported by Flush
	w.WriteByte('\n') //nolint:errcheck // see above
}

func plainRecord(w *bufio.Writer, origin, apex string, e Entry) {
	var b strings.Builder
	if e.owner != "" {
		b.WriteString(Relative(Absolute(e.owner, apex), origin))
	}
	if e.hasTTL {
		b.WriteString(" " + e.ttl.Raw)
	}
	b.WriteString(" " + e.classOrDefault() + " " + e.typ)
	multi := len(e.head) > 0
	for _, f := range e.fields[:max(0, len(e.fields)-1)] {
		multi = multi || len(f.Comments) > 0
	}
	if !multi {
		for _, f := range e.fields {
			b.WriteString(" " + f.Raw)
		}
		b.WriteString(withSpace(joinComments(e.tail)))
		writeLine(w, b.String())
		return
	}
	b.WriteString(" (" + withSpace(joinComments(e.head)))
	writeLine(w, b.String())
	for i, f := range e.fields {
		cs := f.Comments
		if i == len(e.fields)-1 {
			cs = append(cs, e.tail...) //nolint:gocritic // intentionally new slice
		}
		writeLine(w, indent+f.Raw+withSpace(joinComments(cs)))
	}
	writeLine(w, ")")
}
