// SPDX-License-Identifier: Apache-2.0

package masterfile

import (
	"bufio"
	"io"
	"strings"
)

// WritePlain writes the entries without alignment: fields separated by one
// space, owners relative to the $ORIGIN in force, values as written,
// multi-line only when a comment position requires it, comments in place.
// It is deliberately simple and is the reference that [Verify] checks
// [Format] against. Its exact spacing is not part of the contract.
func WritePlain(w io.Writer, apex string, entries []Entry) error {
	bw := bufio.NewWriter(w)
	origin := apex
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
