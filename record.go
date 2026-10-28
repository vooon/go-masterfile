// SPDX-License-Identifier: Apache-2.0

package masterfile

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// ErrInvalidRecord is wrapped by every error of [NewRecord].
var ErrInvalidRecord = errors.New("invalid record")

// NewRecord builds a Record entry "owner [ttl] IN TYPE rdata" from parts,
// without rendering text and parsing it back. A ttl of 0 means no explicit
// TTL. This is a security boundary for values coming from network clients:
// the result is always exactly one record, never a directive, a comment or
// a second record.
//
//   - owner must tokenise as exactly one unquoted item and must not start
//     with "$".
//   - For TXT and SPF, rdata is one raw character-string that becomes one
//     quoted field (see [Quote]); it is not split at 255 bytes.
//   - For other types, rdata must tokenise into one or more items and quoted
//     strings. Line terminators, ";", "(", ")", NUL and unterminated quotes
//     are rejected. Quoted fields stay quoted as written.
//   - rtype must be in the type table.
//
// Errors wrap [ErrInvalidRecord].
func NewRecord(owner string, ttl uint32, rtype uint16, rdata string) (Entry, error) {
	e := Entry{kind: Record, class: "IN", rtype: rtype}
	name, ok := typeByNumber[rtype]
	if !ok {
		return Entry{}, fmt.Errorf("%w: unknown type %d", ErrInvalidRecord, rtype)
	}
	e.typ = name
	toks, err := tokenise(owner)
	if err != nil {
		return Entry{}, fmt.Errorf("%w: owner: %w", ErrInvalidRecord, err)
	}
	if len(toks) != 1 || toks[0].kind != tokItem {
		return Entry{}, fmt.Errorf("%w: owner must be a single name", ErrInvalidRecord)
	}
	if strings.HasPrefix(toks[0].raw, "$") {
		return Entry{}, fmt.Errorf("%w: owner must not start with $", ErrInvalidRecord)
	}
	e.owner = toks[0].raw
	if ttl != 0 {
		e.ttl, e.hasTTL = TTL{Raw: strconv.FormatUint(uint64(ttl), 10), Seconds: ttl}, true
	}
	if strings.TrimSpace(rdata) == "" || strings.ContainsRune(rdata, 0) {
		return Entry{}, fmt.Errorf("%w: empty or invalid rdata", ErrInvalidRecord)
	}
	if e.isText() {
		e.fields = []Field{{Raw: Quote(rdata), Value: rdata, Quoted: true}}
		return e, nil
	}
	toks, err = tokenise(rdata)
	if err != nil {
		return Entry{}, fmt.Errorf("%w: rdata: %w", ErrInvalidRecord, err)
	}
	for _, t := range toks {
		if t.kind != tokItem && t.kind != tokQuoted {
			return Entry{}, fmt.Errorf("%w: rdata: unexpected %q", ErrInvalidRecord, t.raw)
		}
		e.fields = append(e.fields, Field{Raw: t.raw, Value: t.val, Quoted: t.kind == tokQuoted})
	}
	return e, nil
}

// tokenise runs the lexer over s and returns every token before EOF. Line
// terminators are returned as tokens, not swallowed, so callers can reject
// them; a "(" is returned without its group semantics.
func tokenise(s string) ([]token, error) {
	lx, err := newLexer([]byte(s))
	if err != nil {
		return nil, err
	}
	var toks []token
	for {
		lx.inGroup = false
		t, err := lx.next()
		if err != nil {
			return nil, err
		}
		if t.kind == tokEOF {
			return toks, nil
		}
		toks = append(toks, t)
	}
}

// ErrInvalidEntry is wrapped by every error of [NewDirective] and
// [NewComment].
var ErrInvalidEntry = errors.New("invalid entry")

// NewDirective builds a Directive entry from its name ($ORIGIN, $TTL,
// $INCLUDE or $GENERATE, any case) and arguments. Like [NewRecord] it is a
// security boundary: each argument must tokenise as exactly one item or
// quoted string, so it can never add a line, a comment or a second entry;
// a $TTL argument must be a valid TTL. Errors wrap [ErrInvalidEntry].
func NewDirective(name string, args ...string) (Entry, error) {
	e := Entry{kind: Directive, name: strings.ToUpper(name)}
	switch e.name {
	case "$ORIGIN", "$TTL", "$INCLUDE", "$GENERATE":
	default:
		return Entry{}, fmt.Errorf("%w: unknown directive %q", ErrInvalidEntry, name)
	}
	if len(args) == 0 {
		return Entry{}, fmt.Errorf("%w: %s without argument", ErrInvalidEntry, e.name)
	}
	for _, a := range args {
		toks, err := tokenise(a)
		if err != nil {
			return Entry{}, fmt.Errorf("%w: argument %q: %w", ErrInvalidEntry, a, err)
		}
		if len(toks) != 1 || (toks[0].kind != tokItem && toks[0].kind != tokQuoted) {
			return Entry{}, fmt.Errorf("%w: argument %q must be a single item", ErrInvalidEntry, a)
		}
		e.args = append(e.args, Field{Raw: toks[0].raw, Value: toks[0].val, Quoted: toks[0].kind == tokQuoted})
	}
	if e.name == "$TTL" {
		if _, ok := StringToTTL(e.args[0].Value); !ok {
			return Entry{}, fmt.Errorf("%w: invalid TTL %q", ErrInvalidEntry, args[0])
		}
	}
	return e, nil
}

// NewComment builds a Comment entry: one line holding only text, which gets
// a leading "; " when it does not start with ";". Line terminators and NUL
// are rejected, so the text can never become a second line. Errors wrap
// [ErrInvalidEntry].
func NewComment(text string) (Entry, error) {
	if strings.ContainsAny(text, "\r\n\x00") {
		return Entry{}, fmt.Errorf("%w: comment holds a line terminator or NUL", ErrInvalidEntry)
	}
	if !strings.HasPrefix(text, ";") {
		text = "; " + text
	}
	return Entry{kind: Comment, comment: strings.TrimRight(text, " \t")}, nil
}
