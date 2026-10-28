// SPDX-License-Identifier: Apache-2.0

package masterfile

import (
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

// typeNames maps upper-cased RR type names to their numbers; typeByNumber
// is the reverse with canonical (upper-cased) names.
var typeNames, typeByNumber = func() (map[string]uint16, map[uint16]string) {
	names := make(map[string]uint16, len(dns.TypeToString))
	nums := make(map[uint16]string, len(dns.TypeToString))
	for t, n := range dns.TypeToString {
		if t == dns.TypeNone {
			continue
		}
		u := strings.ToUpper(n)
		names[u] = t
		nums[t] = u
	}
	return names, nums
}()

// parseClass recognises IN, CH, HS, NONE, ANY and CLASS<digits>; u must be
// upper-cased already.
func parseClass(u string) (string, bool) {
	switch u {
	case "IN", "CH", "HS", "NONE", "ANY":
		return u, true
	}
	if n, ok := strings.CutPrefix(u, "CLASS"); ok && allDigits(n) {
		if v, err := strconv.ParseUint(n, 10, 16); err == nil {
			return "CLASS" + strconv.FormatUint(v, 10), true
		}
	}
	return "", false
}

// parseType recognises any name in the miekg/dns type table and
// TYPE<digits>; u must be upper-cased already.
func parseType(u string) (uint16, string, bool) {
	if t, ok := typeNames[u]; ok {
		return t, u, true
	}
	if n, ok := strings.CutPrefix(u, "TYPE"); ok && allDigits(n) {
		if v, err := strconv.ParseUint(n, 10, 16); err == nil {
			return uint16(v), "TYPE" + strconv.FormatUint(v, 10), true
		}
	}
	return 0, "", false
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := range len(s) {
		if !isDigit(s[i]) {
			return false
		}
	}
	return true
}

// Parse parses zone file text. The result keeps every entry in order with
// its comments; owners are as written (see [File.ResolveOwners]). Errors
// are *[ParseError] values naming the line. Parse never panics on any
// input and performs no I/O.
func Parse(data []byte) (*File, error) {
	lx, err := newLexer(data)
	if err != nil {
		return nil, err
	}
	f := &File{}
	var toks []token
	for {
		toks = toks[:0]
		line := lx.line
		for {
			tok, err := lx.next()
			if err != nil {
				return nil, err
			}
			if tok.kind == tokEOF {
				if len(toks) == 0 {
					return f, nil
				}
				if err := f.add(toks, line); err != nil {
					return nil, err
				}
				return f, nil
			}
			if tok.kind == tokNewline {
				break
			}
			toks = append(toks, tok)
		}
		if err := f.add(toks, line); err != nil {
			return nil, err
		}
	}
}

func (f *File) add(toks []token, line int) error {
	e, err := buildEntry(toks, line)
	if err != nil {
		return err
	}
	if e.kind == Blank && len(f.Entries) > 0 && f.Entries[len(f.Entries)-1].kind == Blank {
		return nil
	}
	f.Entries = append(f.Entries, e)
	return nil
}

func tokErr(t token, msg string) error {
	return &ParseError{Line: t.line, Col: t.col, Msg: msg}
}

func buildEntry(toks []token, line int) (Entry, error) {
	if len(toks) == 0 {
		return Entry{kind: Blank, line: line}, nil
	}
	first := toks[0]
	switch {
	case first.kind == tokComment:
		return Entry{kind: Comment, line: first.line, comment: first.raw}, nil
	case first.kind == tokItem && strings.HasPrefix(first.raw, "$"):
		return buildDirective(toks)
	}
	return buildRecord(toks)
}

func buildDirective(toks []token) (Entry, error) {
	first := toks[0]
	e := Entry{kind: Directive, line: first.line, name: strings.ToUpper(first.raw)}
	switch e.name {
	case "$ORIGIN", "$TTL", "$INCLUDE", "$GENERATE":
	default:
		return Entry{}, tokErr(first, "unknown directive "+first.raw)
	}
	e.args, e.head, e.tail = collectFields(toks[1:])
	if len(e.args) == 0 {
		return Entry{}, tokErr(first, e.name+" without argument")
	}
	if e.name == "$TTL" {
		if _, ok := StringToTTL(e.args[0].Value); !ok {
			return Entry{}, tokErr(toks[1], "invalid TTL: "+e.args[0].Raw)
		}
	}
	return e, nil
}

// collectFields gathers items and quoted strings as fields, attaching each
// comment to the field before it (head when there is none yet). Comments
// after the last field become the tail; with no fields at all, every
// comment is tail.
func collectFields(toks []token) (fields []Field, head, tail []string) {
	for _, t := range toks {
		switch t.kind {
		case tokItem, tokQuoted:
			fields = append(fields, Field{Raw: t.raw, Value: t.val, Quoted: t.kind == tokQuoted})
		case tokComment:
			if len(fields) == 0 {
				head = append(head, t.raw)
			} else {
				last := &fields[len(fields)-1]
				last.Comments = append(last.Comments, t.raw)
			}
		}
	}
	if len(fields) == 0 {
		return nil, nil, head
	}
	last := &fields[len(fields)-1]
	tail, last.Comments = last.Comments, nil
	return fields, head, tail
}

func buildRecord(toks []token) (Entry, error) {
	first := toks[0]
	e := Entry{kind: Record, line: first.line}
	i := 0
	if first.kind == tokItem && first.col == 1 {
		e.owner = first.raw
		i = 1
	}
	var head []string
	for ; i < len(toks); i++ {
		t := toks[i]
		switch t.kind {
		case tokComment:
			head = append(head, t.raw)
			continue
		case tokLParen, tokRParen:
			continue
		case tokQuoted:
			return Entry{}, tokErr(t, "invalid type/class/ttl: "+t.raw)
		}
		u := strings.ToUpper(t.raw)
		if c, ok := parseClass(u); ok {
			if e.class != "" {
				return Entry{}, tokErr(t, "double class")
			}
			e.class = c
			continue
		}
		if secs, ok := StringToTTL(t.raw); ok {
			if e.hasTTL {
				return Entry{}, tokErr(t, "double TTL")
			}
			e.ttl, e.hasTTL = TTL{Raw: t.raw, Seconds: secs}, true
			continue
		}
		if rt, name, ok := parseType(u); ok {
			e.rtype, e.typ = rt, name
			i++
			break
		}
		return Entry{}, tokErr(t, "invalid type/class/ttl: "+t.raw)
	}
	if e.typ == "" {
		last := toks[len(toks)-1]
		return Entry{}, &ParseError{Line: last.line, Col: last.col + len(last.raw), Msg: "missing type"}
	}
	var fhead []string
	e.fields, fhead, e.tail = collectFields(toks[i:])
	e.head = append(head, fhead...)
	if len(e.fields) == 0 {
		e.tail, e.head = append(e.head, e.tail...), nil
	}
	return e, nil
}
