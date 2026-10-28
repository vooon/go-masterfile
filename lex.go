// SPDX-License-Identifier: Apache-2.0

package masterfile

import (
	"bytes"
	"fmt"
)

// ParseError describes a syntax error in zone file text. Line and Col are
// 1-based; Col counts bytes from the start of the line.
type ParseError struct {
	Line int
	Col  int
	Msg  string
}

// Error implements the error interface as "line L: msg".
func (e *ParseError) Error() string { return fmt.Sprintf("line %d: %s", e.Line, e.Msg) }

type tokKind uint8

const (
	tokEOF tokKind = iota
	tokNewline
	tokItem
	tokQuoted
	tokComment
	tokLParen
	tokRParen
)

// token is one lexical unit of a zone file. Line terminators inside a
// parenthesised group are swallowed by the lexer, so a tokNewline always
// ends an entry.
type token struct {
	kind tokKind
	raw  string // as written; quoted strings include their quotes
	val  string // decoded (items, quoted strings); comment text for comments
	line int
	col  int
}

// lexer is a byte-at-a-time scanner over the input. It tracks the current
// line and the parenthesis group state; everything else is the parser's.
type lexer struct {
	data      []byte
	pos       int
	line      int
	lineStart int
	inGroup   bool
}

func newLexer(data []byte) (*lexer, error) {
	if bytes.HasPrefix(data, []byte("\xEF\xBB\xBF")) {
		return nil, &ParseError{Line: 1, Col: 1, Msg: "byte order mark"}
	}
	return &lexer{data: data, line: 1}, nil
}

func (l *lexer) col() int { return l.pos - l.lineStart + 1 }

func (l *lexer) errorf(format string, args ...any) error {
	return &ParseError{Line: l.line, Col: l.col(), Msg: fmt.Sprintf(format, args...)}
}

// next returns the next token. Blanks are skipped; inside a group line
// terminators are blanks too.
func (l *lexer) next() (token, error) {
	for {
		if l.pos >= len(l.data) {
			if l.inGroup {
				return token{}, l.errorf("unclosed (")
			}
			return token{kind: tokEOF, line: l.line, col: l.col()}, nil
		}
		c := l.data[l.pos]
		switch c {
		case ' ', '\t':
			l.pos++
		case '\n', '\r':
			tok := token{kind: tokNewline, line: l.line, col: l.col()}
			if err := l.eol(); err != nil {
				return token{}, err
			}
			if !l.inGroup {
				return tok, nil
			}
		case 0:
			return token{}, l.errorf("NUL byte")
		case ';':
			return l.comment()
		case '"':
			return l.quoted()
		case '(':
			if l.inGroup {
				return token{}, l.errorf("nested (")
			}
			l.inGroup = true
			tok := token{kind: tokLParen, raw: "(", line: l.line, col: l.col()}
			l.pos++
			return tok, nil
		case ')':
			if !l.inGroup {
				return token{}, l.errorf("unexpected )")
			}
			l.inGroup = false
			tok := token{kind: tokRParen, raw: ")", line: l.line, col: l.col()}
			l.pos++
			return tok, nil
		default:
			return l.item()
		}
	}
}

// eol consumes the line terminator at pos: LF or CRLF. A lone CR is an error.
func (l *lexer) eol() error {
	if l.data[l.pos] == '\r' {
		if l.pos+1 >= len(l.data) || l.data[l.pos+1] != '\n' {
			return l.errorf("CR without LF")
		}
		l.pos++
	}
	l.pos++
	l.line++
	l.lineStart = l.pos
	return nil
}

// comment scans ";" up to, excluding, the line terminator, dropping trailing
// blanks. The terminator itself is left for next.
func (l *lexer) comment() (token, error) {
	tok := token{kind: tokComment, line: l.line, col: l.col()}
	start := l.pos
	for l.pos < len(l.data) {
		switch l.data[l.pos] {
		case '\n':
			goto done
		case '\r':
			if l.pos+1 >= len(l.data) || l.data[l.pos+1] != '\n' {
				return token{}, l.errorf("CR without LF")
			}
			goto done
		case 0:
			return token{}, l.errorf("NUL byte")
		}
		l.pos++
	}
done:
	text := string(bytes.TrimRight(l.data[start:l.pos], " \t"))
	tok.raw, tok.val = text, text
	return tok, nil
}

// quoted scans a "..." string, decoding escapes into val.
func (l *lexer) quoted() (token, error) {
	tok := token{kind: tokQuoted, line: l.line, col: l.col()}
	start := l.pos
	l.pos++
	var val []byte
	for {
		if l.pos >= len(l.data) {
			return token{}, l.errorf("unterminated quoted string")
		}
		switch c := l.data[l.pos]; c {
		case '"':
			l.pos++
			tok.raw, tok.val = string(l.data[start:l.pos]), string(val)
			return tok, nil
		case '\n', '\r':
			return token{}, l.errorf("unterminated quoted string")
		case 0:
			return token{}, l.errorf("NUL byte")
		case '\\':
			if l.pos+1 >= len(l.data) || l.data[l.pos+1] == '\n' || l.data[l.pos+1] == '\r' {
				return token{}, l.errorf("unterminated quoted string")
			}
			if l.data[l.pos+1] == 0 {
				return token{}, l.errorf("NUL byte")
			}
			b, n := decodeEscape(l.data[l.pos:])
			val = append(val, b)
			l.pos += n
		default:
			val = append(val, c)
			l.pos++
		}
	}
}

// item scans a run of bytes that is none of blank, ";", quote, parenthesis
// or line terminator. Backslash escapes follow the quoted-string rules.
func (l *lexer) item() (token, error) {
	tok := token{kind: tokItem, line: l.line, col: l.col()}
	start := l.pos
	var val []byte
scan:
	for l.pos < len(l.data) {
		switch c := l.data[l.pos]; c {
		case ' ', '\t', '\n', '\r', ';', '"', '(', ')':
			break scan
		case 0:
			return token{}, l.errorf("NUL byte")
		case '\\':
			if l.pos+1 >= len(l.data) || l.data[l.pos+1] == '\n' || l.data[l.pos+1] == '\r' {
				return token{}, l.errorf("backslash at end of line")
			}
			if l.data[l.pos+1] == 0 {
				return token{}, l.errorf("NUL byte")
			}
			b, n := decodeEscape(l.data[l.pos:])
			val = append(val, b)
			l.pos += n
		default:
			val = append(val, c)
			l.pos++
		}
	}
	tok.raw, tok.val = string(l.data[start:l.pos]), string(val)
	return tok, nil
}
