// SPDX-License-Identifier: Apache-2.0

package masterfile

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
)

const (
	ownerColumnCap = 24
	indent         = "    "
	longKeyPiece   = 55
)

// longKeys lists the types whose trailing data is split into pieces inside
// parentheses when long, with the number of leading fields kept on the
// record line.
var longKeys = map[string]int{"DNSKEY": 3, "CDNSKEY": 3, "DS": 3, "CDS": 3, "RRSIG": 8}

// lineWriter writes lines without trailing blanks, each ending in LF, and
// collapses blank lines: at most one between entries, none at the start or
// the end. The first write error sticks.
type lineWriter struct {
	w            *bufio.Writer
	wroteAny     bool
	pendingBlank bool
}

func (lw *lineWriter) line(s string) {
	if lw.pendingBlank && lw.wroteAny {
		lw.w.WriteByte('\n') //nolint:errcheck // sticky error reported by Flush
	}
	lw.pendingBlank = false
	lw.wroteAny = true
	lw.w.WriteString(strings.TrimRight(s, " \t")) //nolint:errcheck // see above
	lw.w.WriteByte('\n')                          //nolint:errcheck // see above
}

func (lw *lineWriter) blank() { lw.pendingBlank = true }

// layout holds per-record display decisions and the column widths computed
// in the first pass over the entries.
type layout struct {
	owner  []string // displayed owner per entry index ("" for blank/none)
	ttl    []string // TTL text per entry index ("" when dropped/absent)
	ownerW int
	ttlW   int
	typeW  int
}

// plan runs the first pass: display owners relative to the $ORIGIN in
// force, blank repeated owners, drop TTLs equal to the $TTL in force, and
// measure the columns.
func plan(apex string, entries []Entry) layout {
	l := layout{owner: make([]string, len(entries)), ttl: make([]string, len(entries))}
	origin := apex
	var ttl ttlState
	prev, havePrev := "", false
	for i, e := range entries {
		if e.kind != Record {
			havePrev = false
			ttl.apply(e)
			if e.kind == Directive && e.name == "$ORIGIN" && len(e.args) > 0 {
				origin = Fqdn(e.args[0].Value)
			}
			continue
		}
		if e.owner != "" {
			disp := Relative(Absolute(e.owner, apex), origin)
			if !havePrev || !NameEqual(disp, prev) {
				l.owner[i] = disp
				l.ownerW = max(l.ownerW, min(len(disp), ownerColumnCap))
			}
			prev, havePrev = disp, true
		}
		if e.hasTTL {
			if secs, known := ttl.seconds, ttl.known; !known || secs != e.ttl.Seconds {
				l.ttl[i] = strconv.FormatUint(uint64(e.ttl.Seconds), 10)
				l.ttlW = max(l.ttlW, len(l.ttl[i]))
			}
		}
		l.typeW = max(l.typeW, len(e.typ))
	}
	return l
}

// prefix renders the owner, TTL, class and type columns of a record line,
// ending in one space.
func (l layout) prefix(i int, e Entry) string {
	var b strings.Builder
	b.WriteString(l.owner[i])
	b.WriteString(strings.Repeat(" ", max(0, l.ownerW-len(l.owner[i]))))
	if l.ttlW > 0 {
		b.WriteByte(' ')
		b.WriteString(strings.Repeat(" ", l.ttlW-len(l.ttl[i])))
		b.WriteString(l.ttl[i])
	}
	b.WriteByte(' ')
	b.WriteString(e.classOrDefault())
	b.WriteByte(' ')
	b.WriteString(e.typ)
	b.WriteString(strings.Repeat(" ", l.typeW-len(e.typ)))
	b.WriteByte(' ')
	return b.String()
}

// fieldText renders rdata field i: TXT/SPF strings and CAA's third field
// onward are re-quoted from the decoded value, everything else is verbatim.
func fieldText(e Entry, i int) string {
	f := e.fields[i]
	if e.isText() || (e.typ == "CAA" && i >= 2) {
		return Quote(f.Value)
	}
	return f.Raw
}

func joinComments(cs ...[]string) string {
	var all []string
	for _, c := range cs {
		all = append(all, c...)
	}
	return strings.Join(all, " ")
}

// withSpace prefixes a non-empty comment string with one space.
func withSpace(s string) string {
	if s == "" {
		return ""
	}
	return " " + s
}

// Format writes entries whose owners have been resolved with
// [File.ResolveOwners] against apex in the canonical layout: aligned
// owner, TTL, class, type and value columns; owners relative to the $ORIGIN
// in force and blank when repeated; TTLs equal to the $TTL in force
// dropped; SOA and multi-string TXT records multi-line; long DNSKEY, DS and
// RRSIG data split into 55-byte pieces; comments kept in place. With
// bumpSerial the first SOA's serial is replaced by [Increase] of itself.
// The output is idempotent: formatting it again (without a bump)
// reproduces it byte for byte. Write errors are returned.
func Format(w io.Writer, apex string, entries []Entry, bumpSerial bool) error {
	lw := &lineWriter{w: bufio.NewWriter(w)}
	l := plan(apex, entries)
	bumped := false
	for i, e := range entries {
		switch e.kind {
		case Blank:
			lw.blank()
		case Comment:
			lw.line(e.comment)
		case Directive:
			lw.line(directiveText(e))
		case Record:
			bump := bumpSerial && !bumped && e.typ == "SOA"
			if err := formatRecord(lw, l.prefix(i, e), e, bump); err != nil {
				return err
			}
			bumped = bumped || bump
		}
	}
	return lw.w.Flush()
}

func directiveText(e Entry) string {
	var b strings.Builder
	b.WriteString(e.name)
	for i, a := range e.args {
		b.WriteByte(' ')
		if e.name == "$ORIGIN" && i == 0 {
			b.WriteString(Fqdn(a.Raw))
		} else {
			b.WriteString(a.Raw)
		}
	}
	b.WriteString(withSpace(joinComments(e.Comments())))
	return b.String()
}

func formatRecord(lw *lineWriter, prefix string, e Entry, bumpSerial bool) error {
	if e.typ == "SOA" {
		return formatSOA(lw, prefix, e, bumpSerial)
	}
	if keep, ok := longKeys[e.typ]; ok && len(e.fields) > keep {
		var data strings.Builder
		for _, f := range e.fields[keep:] {
			data.WriteString(f.Raw)
		}
		if data.Len() > longKeyPiece {
			head := make([]string, keep)
			for i := range keep {
				head[i] = e.fields[i].Raw
			}
			lw.line(prefix + strings.Join(head, " ") + " (" + withSpace(joinComments(e.Comments())))
			s := data.String()
			for len(s) > longKeyPiece {
				lw.line(indent + s[:longKeyPiece])
				s = s[longKeyPiece:]
			}
			lw.line(indent + s)
			lw.line(")")
			return nil
		}
	}
	multi := len(e.head) > 0 || (e.isText() && len(e.fields) > 1)
	for _, f := range e.fields[:max(0, len(e.fields)-1)] {
		multi = multi || len(f.Comments) > 0
	}
	texts := make([]string, len(e.fields))
	for i := range e.fields {
		texts[i] = fieldText(e, i)
	}
	if !multi {
		lw.line(strings.TrimRight(prefix+strings.Join(texts, " "), " ") + withSpace(joinComments(e.tail)))
		return nil
	}
	lw.line(prefix + "(" + withSpace(joinComments(e.head)))
	width := 0
	for i, f := range e.fields {
		if len(f.Comments) > 0 || (i == len(e.fields)-1 && len(e.tail) > 0) {
			width = max(width, len(texts[i]))
		}
	}
	for i, f := range e.fields {
		cs := f.Comments
		if i == len(e.fields)-1 {
			cs = append(cs, e.tail...) //nolint:gocritic // intentionally new slice
		}
		if len(cs) == 0 {
			lw.line(indent + texts[i])
			continue
		}
		lw.line(indent + texts[i] + strings.Repeat(" ", width-len(texts[i])) + " " + joinComments(cs))
	}
	lw.line(")")
	return nil
}

// soaLabels are the generated comments for the SOA's numeric fields after
// the serial.
var soaLabels = [...]string{"; refresh", "; retry", "; expire", "; minimum"}

func formatSOA(lw *lineWriter, prefix string, e Entry, bumpSerial bool) error {
	if len(e.fields) != 7 {
		return fmt.Errorf("line %d: SOA has %d fields, want 7", e.line, len(e.fields))
	}
	lw.line(prefix + e.fields[0].Raw + " " + e.fields[1].Raw + " (" +
		withSpace(joinComments(e.head, e.fields[0].Comments, e.fields[1].Comments)))
	values := make([]string, 5)
	width := 0
	for i := range 5 {
		values[i] = e.fields[2+i].Raw
		width = max(width, len(values[i]))
	}
	if bumpSerial {
		values[0] = Increase(values[0])
		width = max(width, len(values[0]))
	}
	for i := range 5 {
		cs := e.fields[2+i].Comments
		if i == 4 {
			cs = append(cs, e.tail...) //nolint:gocritic // intentionally new slice
		}
		user := joinComments(cs)
		var comment string
		if i == 0 {
			comment = serialComment(values[0], user)
		} else if comment = user; comment == "" || comment == soaLabels[i-1] {
			comment = soaLabels[i-1]
		}
		lw.line(indent + values[i] + strings.Repeat(" ", width-len(values[i])) + " " + comment)
	}
	lw.line(")")
	return nil
}

// Reformat parses data, finds the apex with [File.Origin] (falling back to
// the root "." when none is known), resolves owners and writes the
// canonical layout to w. It is Parse, Origin, ResolveOwners and Format in
// one call, for formatter commands and tests.
func Reformat(data []byte, originHint string, w io.Writer, bumpSerial bool) error {
	f, err := Parse(data)
	if err != nil {
		return err
	}
	apex, _ := f.Origin(originHint)
	if apex == "" {
		apex = "."
	}
	if err := f.ResolveOwners(apex); err != nil {
		return err
	}
	return Format(w, apex, f.Entries, bumpSerial)
}
