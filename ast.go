// SPDX-License-Identifier: Apache-2.0

package masterfile

import (
	"slices"
	"strings"
)

// Kind classifies an entry.
type Kind int

// Entry kinds.
const (
	Blank     Kind = iota // an empty line (runs are collapsed into one)
	Comment               // a line holding only a comment
	Directive             // $ORIGIN, $TTL, $INCLUDE or $GENERATE
	Record                // a resource record
)

// String returns the kind's name.
func (k Kind) String() string {
	switch k {
	case Blank:
		return "blank"
	case Comment:
		return "comment"
	case Directive:
		return "directive"
	case Record:
		return "record"
	}
	return "kind(" + itoa(int(k)) + ")"
}

// Field is one rdata field or directive argument.
type Field struct {
	Raw      string   // as written, including quotes and escapes
	Value    string   // decoded: escapes resolved, quotes removed
	Quoted   bool     // written as a quoted string
	Comments []string // comments following this field, before the next
}

func (f Field) clone() Field {
	f.Comments = slices.Clone(f.Comments)
	return f
}

func cloneFields(fs []Field) []Field {
	if fs == nil {
		return nil
	}
	out := make([]Field, len(fs))
	for i, f := range fs {
		out[i] = f.clone()
	}
	return out
}

// Entry is one zone file entry: a blank line, a comment line, a directive
// or a record. Entries are immutable values: methods that change an entry
// return a new one, so copies never alias each other and can be inserted
// into slices and compared freely. The zero Entry is a blank line.
type Entry struct {
	kind    Kind
	line    int
	comment string  // Comment: the full text including ";"
	name    string  // Directive: "$ORIGIN" etc., upper-cased
	args    []Field // Directive arguments
	owner   string  // Record: as written, "" when inherited/unknown
	ttl     TTL     // Record: valid when hasTTL
	hasTTL  bool
	class   string // Record: upper-cased, "" when absent
	typ     string // Record: upper-cased
	rtype   uint16 // Record: numeric type
	fields  []Field
	head    []string // comments after "(" before the first field
	tail    []string // comments after the last field / end of line
}

// Kind returns the entry kind.
func (e Entry) Kind() Kind { return e.kind }

// Line returns the 1-based line of the entry's first line in the parsed
// text, or 0 for entries built by hand.
func (e Entry) Line() int { return e.line }

// Comment returns the text of a Comment entry including the leading ";".
func (e Entry) Comment() string { return e.comment }

// Name returns a Directive entry's name, upper-cased, such as "$ORIGIN".
func (e Entry) Name() string { return e.name }

// Args returns a copy of a Directive entry's arguments.
func (e Entry) Args() []Field { return cloneFields(e.args) }

// Owner returns a Record entry's owner: relative to the apex for an entry
// that came from [Parse], as given for one built by hand; "" when the
// owner is inherited from the previous record and could not be resolved.
func (e Entry) Owner() string { return e.owner }

// TTL returns a Record entry's explicit TTL and whether it has one.
func (e Entry) TTL() (TTL, bool) { return e.ttl, e.hasTTL }

// Class returns a Record entry's class, upper-cased, or "" when absent.
func (e Entry) Class() string { return e.class }

// Type returns a Record entry's type name, upper-cased ("A", "TYPE65280").
func (e Entry) Type() string { return e.typ }

// RType returns a Record entry's numeric type.
func (e Entry) RType() uint16 { return e.rtype }

// Fields returns a copy of a Record entry's rdata fields.
func (e Entry) Fields() []Field { return cloneFields(e.fields) }

// Head returns a copy of the comments between "(" and the first field.
func (e Entry) Head() []string { return slices.Clone(e.head) }

// Tail returns a copy of the comments after the last field or at the end
// of the entry's line.
func (e Entry) Tail() []string { return slices.Clone(e.tail) }

// Comments returns every comment attached to the entry in file order: the
// comment of a Comment entry, or head, per-field and tail comments.
func (e Entry) Comments() []string {
	if e.kind == Comment {
		return []string{e.comment}
	}
	var out []string
	out = append(out, e.head...)
	for _, f := range e.allFields() {
		out = append(out, f.Comments...)
	}
	return append(out, e.tail...)
}

func (e Entry) allFields() []Field {
	if e.kind == Directive {
		return e.args
	}
	return e.fields
}

// Values returns a Record entry's rdata fields decoded (escapes resolved,
// quotes removed), or a Directive entry's decoded arguments.
func (e Entry) Values() []string {
	fs := e.allFields()
	out := make([]string, len(fs))
	for i, f := range fs {
		out[i] = f.Value
	}
	return out
}

// RawValues returns a Record entry's rdata fields as written, or a
// Directive entry's arguments as written.
func (e Entry) RawValues() []string {
	fs := e.allFields()
	out := make([]string, len(fs))
	for i, f := range fs {
		out[i] = f.Raw
	}
	return out
}

// Content returns the record's content in the PowerDNS form: for TXT and
// SPF the concatenation of the decoded strings, for every other type the
// decoded fields joined by one space.
func (e Entry) Content() string {
	sep := " "
	if e.isText() {
		sep = ""
	}
	return strings.Join(e.Values(), sep)
}

// isText reports whether the record's rdata is character-strings (TXT, SPF).
func (e Entry) isText() bool { return e.typ == "TXT" || e.typ == "SPF" }

// WithComments returns a copy of the entry with the comments appended to its
// last line as one comment joined by single spaces. Comments without a
// leading ";" get one. Empty comments are ignored.
func (e Entry) WithComments(comments ...string) Entry {
	var parts []string
	for _, c := range comments {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		if !strings.HasPrefix(c, ";") {
			c = "; " + c
		}
		parts = append(parts, c)
	}
	if len(parts) == 0 {
		return e
	}
	joined := strings.Join(parts, " ")
	e.args, e.fields = cloneFields(e.args), cloneFields(e.fields)
	e.head = slices.Clone(e.head)
	switch e.kind {
	case Comment:
		e.comment += " " + joined
	case Blank:
		e.kind, e.comment = Comment, joined
	default:
		e.tail = append(slices.Clone(e.tail), joined)
	}
	return e
}

// WithOwner returns a copy of a Record entry with its owner replaced; an
// empty name clears the owner so it is inherited. It is the caller's job
// to pass a single owner item (see [NewRecord]).
func (e Entry) WithOwner(name string) Entry {
	e.owner = name
	return e
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
