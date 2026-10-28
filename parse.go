// SPDX-License-Identifier: Apache-2.0

package masterfile

import (
	"fmt"
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
	if n, ok := strings.CutPrefix(u, "CLASS"); ok {
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
	if n, ok := strings.CutPrefix(u, "TYPE"); ok {
		if v, err := strconv.ParseUint(n, 10, 16); err == nil {
			return uint16(v), "TYPE" + strconv.FormatUint(v, 10), true
		}
	}
	return 0, "", false
}

// Parse parses zone file text into a [Zone]. Every entry is kept in order
// with its comments. The apex is the owner of the first SOA record,
// resolved with apex as the origin in force before any $ORIGIN line; with
// no SOA it is apex itself, else the first $ORIGIN, else the root ".". A
// non-empty apex is also an assertion: when the SOA names a different zone,
// [ErrApexMismatch] is returned, so a file edited over time keeps its
// origin. Names are resolved against the origin in force, which before any
// $ORIGIN line is apex, or the root when apex is empty (a relative name is
// then taken as absolute, as the reference parser does); the apex found
// only decides what the resolved owners are relative to (see [Zone]), so a
// file without origin is never reinterpreted. Syntax errors are
// *[ParseError] values naming the line. Parse never panics on any input
// and performs no I/O.
func Parse(data []byte, apex string) (*Zone, error) {
	lx, err := newLexer(data)
	if err != nil {
		return nil, err
	}
	z := &Zone{}
	var toks []token
	for {
		toks = toks[:0]
		line := lx.line
		eof := false
		for !eof {
			tok, err := lx.next()
			if err != nil {
				return nil, err
			}
			if tok.kind == tokNewline {
				break
			}
			if eof = tok.kind == tokEOF; !eof {
				toks = append(toks, tok)
			}
		}
		if len(toks) > 0 || !eof {
			if err := z.add(toks, line); err != nil {
				return nil, err
			}
		}
		if eof {
			break
		}
	}
	found, known := findApex(z.Entries, apex)
	if apex != "" && !NameEqual(found, Fqdn(apex)) {
		return nil, fmt.Errorf("%w: file has %s, caller expects %s", ErrApexMismatch, found, Fqdn(apex))
	}
	resolveOwners(z.Entries, apex, found)
	z.apex, z.origin, z.noOrigin = found, startOrigin(apex), !known
	return z, nil
}

func (z *Zone) add(toks []token, line int) error {
	e, err := buildEntry(toks, line)
	if err != nil {
		return err
	}
	if e.kind == Blank && len(z.Entries) > 0 && z.Entries[len(z.Entries)-1].kind == Blank {
		return nil
	}
	z.Entries = append(z.Entries, e)
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
	e := Entry{kind: Directive, line: first.line, name: upperASCII(first.raw)}
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
			if fields == nil {
				fields = make([]Field, 0, len(toks))
			}
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
		u := upperASCII(t.raw)
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
