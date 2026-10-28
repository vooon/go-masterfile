# masterfile: specification for a new zone file module

Status: draft for implementation in a fresh session. Target: a new Go module,
Apache-2.0, that replaces `pkg/zonefile` in zoneomatic.

## 0. Ground rules for the implementer

This is a clean-room specification. The module is a new work written from this
document and the RFCs it cites, not a port of existing code.

- Do not open, read, copy or paraphrase zoneomatic's current `pkg/zonefile`
  (any revision), `cmd/dnsfmt`, or the two upstream projects they descend from
  (a Go zone file tokenizer library and a zone formatting tool). Do not search
  for them. If a question is not answered here, decide from the RFCs and this
  document's intent, and note the decision in the module's `docs/DESIGN.md`.
- The expected outputs in this document are behavioural requirements: they
  were produced by the system the module replaces and define what zoneomatic
  users see. Output formats are not code. Reproduce them exactly.
- The only third-party dependency is `github.com/miekg/dns` (BSD-3-Clause),
  used for the RR type and class name tables and as the reference parser in
  verification. Nothing else, including no code generation from other zone
  libraries.
- Every source file starts with the Apache-2.0 SPDX header. The module has its
  own `go.mod`, `LICENSE`, `README.md`, `docs/DESIGN.md`, tests and golden files, and
  no dependency on zoneomatic. zoneomatic will depend on it.

## 1. Names and layout

- Module path: `github.com/vooon/masterfile`. Package: `masterfile`. The RFC
  1035 term is "master file"; the name must not contain "zonefile" or
  "dnsfmt".
- No command in this module. The formatter command (`mfmt`, section 6.9) is
  a thin wrapper over `Reformat` and lives in zoneomatic, so the library
  pulls in nothing beyond `miekg/dns` for its main job.
- Suggested files: `doc.go`, `lex.go`, `parse.go`, `ast.go`, `names.go`,
  `ttl.go`, `escape.go`, `origin.go`, `record.go`, `equal.go`, `format.go`,
  `plain.go`, `serial.go`, `verify.go`, `*_test.go`, `testdata/`.
- Go 1.27 or later. No CGO. `go vet` and `golangci-lint` (default linters)
  clean. All exported identifiers documented. This is a new work: use
  current language and standard library features (generics, range-over-func
  iterators, `slices`/`maps`, newer `bytes`/`strings` helpers) freely where
  they simplify the code; iterator forms may be offered alongside, not in
  place of, the API shapes named in section 7.

## 2. Purpose

zoneomatic edits DNS zone files that humans also edit, and that another
program (CoreDNS, BIND, Knot) serves. The module must:

1. parse a zone file keeping everything a human put there: comments in every
   position, blank lines, directives, the written form of values;
2. give records stable identities (absolute owner, type, values, effective
   TTL) so they can be found, compared, replaced and removed;
3. build new records safely from parts coming from network clients;
4. write the file back in one canonical layout, byte-identical whether written
   by the server or by the formatter command;
5. prove, with an independent parser, that the written file holds exactly the
   intended records and comments before it replaces the original.

Non-goals: serving DNS, DNSSEC signing, `$INCLUDE` expansion, `$GENERATE`
expansion, validating RDATA syntax per type (the reference parser does that
in verification), preserving original whitespace.

## 3. Input language

RFC 1035 section 5.1 with the common extensions below. Input is a byte slice;
the module never reads files itself except in the command.

### 3.1 Bytes and lines

- Lines end with LF or CRLF. A CR not followed by LF is an error ("CR without
  LF", with line number): parsers disagree on it.
- A NUL byte anywhere is an error.
- A final line without a line terminator is accepted.
- A UTF-8 BOM is an error ("byte order mark"): no zone file parser expects it.
- Bytes 0x80..0xFF are opaque: kept, never case-folded, never decoded.

### 3.2 Tokens

- Blank: space (0x20) and tab (0x09).
- Comment: `;` to end of line (not inside a quoted string). The comment text
  includes the `;` and everything after it up to, excluding, the line
  terminator, with trailing blanks removed.
- Quoted string: `"` … `"`. Inside, `\` escapes the next byte; `\DDD` (exactly
  three decimal digits, value 0..255) is one byte; `\"` is a quote; a line
  terminator inside a quoted string is an error ("unterminated quoted
  string"), as is end of input inside one.
- Parentheses: `(` starts a group, `)` ends it. Inside a group, line
  terminators are blanks, so an entry may span lines. A `(` inside a group is
  an error ("nested ("), a `)` outside is an error ("unexpected )"), end of
  input inside a group is an error ("unclosed (").
- Item: a run of bytes that is none of the above (not blank, `;`, `"`, `(`,
  `)`, line terminator). `\` in an item escapes the next byte with the same
  rules as in quoted strings, so `a\;b` and `a\ b` are single items. An item
  may be a domain name, number, class, type or RDATA field.

### 3.3 Entries

An entry is one logical line: a line plus continuation lines joined by a
group. Kinds:

- **Blank**: no items and no comment. Consecutive blank lines are kept as a
  single blank entry (the formatter writes at most one blank line).
- **Comment**: no items, one comment (possibly indented). Several comment
  lines are several entries.
- **Directive**: first item starts with `$`. Recognised: `$ORIGIN name`,
  `$TTL ttl`, `$INCLUDE file [origin]`, `$GENERATE range lhs [ttl] [class]
  type rhs`. Any other `$NAME` is an error ("unknown directive"). A directive
  without its argument is an error. `$ORIGIN` and `$TTL` affect parsing
  state (section 4); `$INCLUDE` and `$GENERATE` are kept as written and have
  no effect (the module does not open files or expand ranges). A directive may
  carry a trailing comment.
- **Record**: `[owner] [ttl] [class] type rdata...` where:
  - the owner is present when the line starts with an item (no leading
    blank); when the line starts with a blank the owner is inherited from the
    previous record (section 4.2);
  - ttl and class may appear in either order, each at most once ("double
    TTL", "double class" are errors);
  - a class is `IN`, `CH`, `HS`, `NONE`, `ANY` or `CLASS` followed by digits,
    case-insensitive;
  - a type is any name in miekg/dns's `StringToType` table or `TYPE` followed
    by digits, case-insensitive. An item that is neither ttl, class nor type
    where the type is expected is an error ("invalid type/class/ttl: ...");
  - missing type is an error ("missing type");
  - rdata is zero or more items or quoted strings; zero is accepted at parse
    time (verification rejects what the reference parser rejects);
  - comments may appear after `(`, after any rdata field, and at the end.

### 3.4 TTL syntax

A TTL is a decimal number of seconds, or a BIND duration: a sequence of
`<digits><unit>` with units `s m h d w` (any case), optionally ending in bare
digits (seconds), e.g. `1h30m`, `2W`, `90`. Values must fit in 32 bits;
overflow and an empty string are errors. `StringToTTL(s) (uint32, bool)`
exposes this.

## 4. Semantics

### 4.1 Origin and apex

- The current origin starts as the caller's hint (may be empty) and changes
  at each `$ORIGIN`. A `$ORIGIN` value is always taken as absolute (a trailing
  dot is added if missing), when parsing and when writing.
- `@` means the current origin.
- A name ending in `.` is absolute. Any other name is relative to the current
  origin; with no origin known, a relative name is taken as absolute (this is
  what the reference parser does).
- The **apex** of a file is the owner of the first SOA record, resolved as
  above. `Origin(hint string) (apex string, soa *Record)` returns it, or,
  with no SOA, the first `$ORIGIN`, else the hint, with a nil record. A bare
  `@` SOA owner with no origin at all yields an empty apex.

### 4.2 Owner resolution

`ResolveOwners(apex string) error` rewrites every record so that its owner is
explicit and **relative to the apex**: `@` for the apex, `www` for
`www.<apex>`, and the absolute name for names outside the apex. Inherited
(blank) owners are filled from the previous record; a record with nothing to
inherit is left ownerless. After this, an entry's meaning does not depend on
its position or on `$ORIGIN` lines, so entries can be moved, inserted and
compared.

Name comparison is case-insensitive for ASCII letters only (RFC 4343); other
bytes compare exactly.

### 4.3 TTL state

- `$TTL` sets the default TTL for following records (RFC 2308).
- A record's **effective TTL** is its own TTL if present, else the `$TTL` in
  force, else unknown.
- `Entry.Equal` compares two entries literally (same kind, owner, class, type,
  values, and same explicit TTL or both absent); comments are ignored.
- `EntriesEqual(a, b []Entry) bool` compares lists by meaning: same length,
  pairwise `Equal` ignoring TTL, and equal effective TTLs (both unknown is
  equal; known vs unknown is not). This is what decides whether an edit
  changed anything.

### 4.4 Values

- `Values()` returns rdata fields decoded (escapes resolved, quotes removed).
- `RawValues()` returns them as written (for writing back unchanged).
- TXT and SPF content is the concatenation of their decoded strings; other
  types' content is their decoded fields joined by one space. `Content()`
  returns this (the PowerDNS "content" form).

## 5. Data model

```go
type File struct {
    Entries []Entry
    // trailing bytes that formed no entry are dropped; nothing else is kept
}

type Kind int // Blank, Comment, Directive, Record

type Entry struct {
    Kind     Kind
    Comment  string      // Comment entries: the full comment text incl. ";"
    Name     string      // Directive: "$ORIGIN" etc. (upper-cased)
    Args     []Field     // Directive arguments
    Owner    string      // Record: as written, "" when inherited
    TTL      *TTL        // Record: nil when absent
    Class    string      // Record: upper-cased, "" when absent
    Type     string      // Record: upper-cased
    RType    uint16      // Record: numeric type (TYPE### parsed)
    Fields   []Field     // Record: rdata
    Head     []string    // comments after "(" before the first field
    Tail     []string    // comments after the last field / end of line
    Line     int         // 1-based line of the entry's first line
}

type Field struct {
    Raw      string   // as written, including quotes and escapes
    Value    string   // decoded
    Quoted   bool
    Comments []string // comments following this field, before the next
}

type TTL struct {
    Raw     string // as written ("1h", "3600")
    Seconds uint32
}
```

The exact shape may differ (unexported fields, methods instead of fields) but
every piece of information above must be reachable, and entries must be
values that can be copied, inserted into slices and compared without aliasing
surprises: mutating a copy must not change the original.

## 6. Operations

### 6.1 Parse

`Parse(data []byte) (*File, error)`; errors are `*ParseError{Line, Col,
Msg}` with `Error()` as `"line L: msg"`. Parsing never panics on any input
(fuzz-tested). Parsing is a plain function over bytes: no goroutines, no
channels.

### 6.2 Names

- `Fqdn(s string) string`: adds a trailing dot if missing.
- `NameEqual(a, b string) bool`: section 4.2 rule.
- `Relative(name, origin string) string`: for an absolute name under the
  absolute origin, the relative part; the origin itself gives `@`; a name not
  under the origin, or not absolute, is returned unchanged. The suffix must
  match on a label boundary: `myexample.com.` is not under `example.com.`, and
  an escaped dot (`\.`) is not a boundary.
- `Absolute(name, origin string) string`: section 4.1 rule.

### 6.3 Building records

`NewRecord(owner string, ttl uint32, rtype uint16, rdata string) (Entry,
error)` creates a Record entry `owner [ttl] IN TYPE rdata` with `ttl == 0`
meaning no explicit TTL. It must not render text and parse it back. Rules:

- `owner` is tokenised with the item rules; it must be exactly one item
  (not quoted). Otherwise error.
- For TXT and SPF, `rdata` is one raw character-string: it becomes one quoted
  field, escaped by `Quote` (6.4). Strings over 255 bytes are not split; the
  reference parser rejects them at verification.
- For other types, `rdata` is tokenised; it must consist only of items,
  quoted strings and blanks, at least one field. A line terminator, `;`, `(`,
  `)`, NUL or an unterminated quote is an error. Quoted fields stay quoted
  as written (CAA, HINFO, NAPTR, ...).
- Unknown `rtype` (not in the type table) is an error.
- Errors wrap `ErrInvalidRecord`.

This is a security boundary: values arrive from HTTP and DNS UPDATE clients,
and a value must never add a second record, a directive or a comment.

### 6.4 Quoting and escaping

`Quote(s string) string` renders a raw string as a zone file quoted string:
`"` and `\` are prefixed with `\`; bytes below 0x20 and byte 0x7F are written
as `\DDD` (three digits); all other bytes, including UTF-8 and bytes above
0x7F, are copied. The result reads back (3.2) to exactly `s`. Go's `%q` is not
suitable (zone parsers do not know `\n`, `\x`, `\u`).

### 6.5 Formatting

`Format(w io.Writer, apex string, entries []Entry, bumpSerial bool) error`
writes entries whose owners have been resolved (4.2) in the canonical layout.
`Reformat(data []byte, originHint string, w io.Writer, bumpSerial bool)
error` is Parse, Origin, ResolveOwners, Format in one call (the formatter
command and tests use it; an empty apex falls back to `.`). Write errors are
returned (first error wins), never ignored.

Layout rules, all of which the examples in section 8 exercise:

1. **Owner column.** The displayed owner is the record's absolute name made
   relative to the `$ORIGIN` in effect at that line (the apex before any
   `$ORIGIN`). Owners are left-aligned in a column whose width is the longest
   displayed owner, capped at 24; longer owners overflow the column (one
   space, then the next column). A record whose displayed owner equals the
   previous record's displayed owner (4.2 comparison) gets a blank owner,
   unless a comment, blank line or directive entry came between them; then
   the owner is written again.
2. **TTL column.** Only records whose TTL is present and differs from the
   `$TTL` in force get a TTL; a TTL equal to it is redundant and dropped. If
   no record in the file keeps a TTL, there is no TTL column. Otherwise the
   column is right-aligned to the widest kept TTL (written as decimal
   seconds), and records without one get blanks.
3. **Class and type.** Class is written as parsed, `IN` when absent. Types
   are left-aligned to the longest type in the file.
4. **Values** are written as in `RawValues` (no rewriting of names or
   durations), separated by one space, except: TXT/SPF strings are
   re-quoted with `Quote` of the decoded value; CAA's third field onward
   likewise; everything else verbatim.
5. **One line or many.** A record is one line, with its trailing comments
   joined by one space at the end, unless it must be multi-line: TXT/SPF with
   more than one string, a comment after `(` (Head), or a comment after any
   field but the last. Multi-line form is `<prefix>(<head comments>` then one
   field per line indented by four spaces, each followed by its comments
   aligned one space after the longest commented field, then `)` on its own
   line.
6. **SOA** is always multi-line: `<prefix>MNAME RNAME (` followed by comments
   after `(` and after the first two fields, then the five numeric fields one
   per line, indented four spaces, left-aligned to the widest, each with a
   comment: `; serial  <date>` plus any user comment (6.6), then `; refresh`,
   `; retry`, `; expire`, `; minimum`. A user comment on these four fields
   replaces the label; a comment equal to the label is regenerated. A SOA
   with other than seven fields is an error.
7. **Long keys.** DNSKEY, CDNSKEY, DS, CDS and RRSIG: the first 3 fields (8
   for RRSIG) stay on the record line; the remaining fields are concatenated
   and, when longer than 55 bytes, written in 55-byte pieces one per line
   indented four spaces inside `( )`, with all comments on the first line.
   Shorter data stays on one line.
8. **Directives** are written as `$NAME arg arg` plus trailing comment;
   `$ORIGIN` arguments are made absolute.
9. **Comments and blank lines** are written as-is, in place. Leading and
   trailing blank lines of the file are dropped; runs collapse to one.
10. **No trailing blanks** on any line; lines end with LF; the file ends with
    LF.
11. **Serial.** With `bumpSerial`, the SOA serial is replaced by
    `Increase(serial)` (6.6) before writing.

Formatting must be idempotent: formatting the output again without bumping
the serial reproduces it byte for byte. Formatting entries loaded from a file
and formatting the file text (Reformat) produce identical bytes.

### 6.6 Serial numbers

- A serial is a **date serial** if it is in `1990010100..2099123199` and its
  first eight digits are a valid calendar date (`YYYYMMDD`); otherwise it is
  a **Unix time serial**. Non-numeric serials are written back unchanged.
- `Increase(serial string) string`: a Unix time serial becomes
  `max(now, serial+1)`; a date serial is incremented by one (no date logic:
  `2024123199` becomes `2024123200`). Two bumps within one second still
  increase.
- The generated serial comment is `; serial  ` (two spaces) followed by a
  rendering: for a Unix time serial the UTC time in RFC 1123 form
  (`Sun, 01 Sep 2024 09:30:00 UTC`); for a date serial the date in the form
  `Sun, 01 Sep 2024 #01` where `#nn` is the two-digit sequence. Anything the
  user wrote after an existing generated comment is kept after it, separated
  by one space; a user comment that is not a generated one is kept whole.
- `UserComment(c string) string` returns the user part of a serial comment
  (strips `; serial`, the two spaces and one of the two renderings) and other
  comments unchanged; verification uses it so regenerated dates do not count
  as lost comments.

### 6.7 Plain writer

`WritePlain(w io.Writer, apex string, entries []Entry) error` writes the same
entries without alignment: one field-separating space, owners relative to the
current `$ORIGIN`, raw values, multi-line only when a comment position
requires it, comments in place. It is deliberately simple and is the
reference that `Verify` checks `Format` against. Its exact spacing is not
part of the contract.

### 6.8 Verification

`Verify(apex string, plain, formatted []byte) error` parses both texts with
`miekg/dns`'s `ZoneParser` (origin `apex`, `$INCLUDE` disallowed) and
requires:

- both parse;
- the multisets of records, as `rr.String()` lower-cased with the SOA serial
  zeroed, are equal; a difference is reported as `-lost` / `+added` entries;
- every user comment (6.6) found in `plain` by this module's parser occurs in
  the comments of `formatted`.

Errors wrap `ErrUnsafeWrite`. Helpers `Records(apex, data) (map[string]int,
error)` and `Comments(data) ([]string, error)` are exported for tests.

### 6.9 Command `mfmt` (lives in zoneomatic, not in this module)

```
mfmt [--no-inc] [-o ORIGIN] [-r] [FILE]...
```

Reads standard input (no FILE or `-`) or each file; prints the formatted
zone, or with `-r` rewrites each file atomically (temp file in the same
directory, same permission bits, rename). `-i/--inc` (default true, negatable
as `--no-inc`) bumps the serial. `-o` sets the origin hint. Exit status 1 with
the parse error on stderr for a bad file. It is zoneomatic's `cmd/mfmt`
(replacing `cmd/dnsfmt`), built on `Reformat`; this module only guarantees
that `Reformat` provides everything the command needs. Flag library choice is
zoneomatic's.

## 7. API summary

| Function | Purpose |
|---|---|
| `Parse(data) (*File, error)` | 6.1 |
| `(*File).Origin(hint) (string, *Entry)` | 4.1 |
| `(*File).ResolveOwners(apex) error` | 4.2 |
| `NewRecord(owner, ttl, rtype, rdata) (Entry, error)` | 6.3 |
| `(Entry).Equal(Entry) bool`, `EntriesEqual(a, b) bool` | 4.3 |
| `(Entry).Values/RawValues/Content/Comments` | 4.4 |
| `Format`, `Reformat` | 6.5 |
| `WritePlain` | 6.7 |
| `Verify`, `Records`, `Comments` | 6.8 |
| `Fqdn`, `NameEqual`, `Relative`, `Absolute` | 6.2 |
| `StringToTTL` | 3.4 |
| `Quote` | 6.4 |
| `Increase`, `UserComment` | 6.6 |
| `ErrInvalidRecord`, `ErrUnsafeWrite`, `*ParseError` | errors |

## 8. Examples (normative)

### 8.1 Full layout

Input:

```
; zone for the lab
$ORIGIN lab.example.
$TTL 1h
@  3600 IN SOA ns1 hostmaster.lab.example. ( 2024090101 ; bump me
      2h 30m 2w 1h )
   IN NS  ns1
   IN NS ns2.lab.example.
ns1       IN A    192.0.2.53
          IN AAAA 2001:db8::53

; web
www       300 IN A    192.0.2.80
www       IN   TXT  "v=spf1 -all"
          IN   TXT  ("part one" "part two")
_25._tcp.mail IN TLSA 3 1 1 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
@      IN CAA  0 issue "ca.example; validationmethods=dns-01"
@  IN MX 10 mail
@ IN DNSKEY 257 3 13 kXKkvWU3vGYfTJGl3nTy6g5zDpqwXUd6XaMnKzEZeIYbp5c+ThYZ2hCWEOYoqNxzR4KYhUtKGnc4PbMBMuGl0w==
$ORIGIN guests.lab.example.
alice  IN A 192.0.2.101  ; laptop
       IN A 192.0.2.102
www.lab.example. IN A 192.0.2.80
```

`Reformat(input, "", w, false)` must write exactly:

```
; zone for the lab
$ORIGIN lab.example.
$TTL 1h
@                    IN SOA    ns1 hostmaster.lab.example. (
    2024090101 ; serial  Sun, 01 Sep 2024 #01 ; bump me
    2h         ; refresh
    30m        ; retry
    2w         ; expire
    1h         ; minimum
)
                     IN NS     ns1
                     IN NS     ns2.lab.example.
ns1                  IN A      192.0.2.53
                     IN AAAA   2001:db8::53

; web
www              300 IN A      192.0.2.80
                     IN TXT    "v=spf1 -all"
                     IN TXT    (
    "part one"
    "part two"
)
_25._tcp.mail        IN TLSA   3 1 1 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
@                    IN CAA    0 issue "ca.example; validationmethods=dns-01"
                     IN MX     10 mail
                     IN DNSKEY 257 3 13 (
    kXKkvWU3vGYfTJGl3nTy6g5zDpqwXUd6XaMnKzEZeIYbp5c+ThYZ2hC
    WEOYoqNxzR4KYhUtKGnc4PbMBMuGl0w==
)
$ORIGIN guests.lab.example.
alice                IN A      192.0.2.101 ; laptop
                     IN A      192.0.2.102
www.lab.example.     IN A      192.0.2.80
```

Points to notice: the SOA's `3600` equals `$TTL 1h` and is dropped while
`300` is kept, giving a 3-wide TTL column; the owner column is 16 wide
(`www.lab.example.`) plus the TTL column; `www` is blank on the TXT lines
(same owner, nothing between), while `@` is written again for CAA after the
TLSA record; under `$ORIGIN guests.lab.example.` the apex-relative owner
`www` is displayed absolute because it is not under the current origin; the
`; bump me` comment survives after the generated serial text; `( ... )` of
the original SOA and TXT are re-laid out.

### 8.2 TTL column

Input:

```
$ORIGIN example.org.
$TTL 30
@ IN SOA ns hostmaster 2024041300 4H 1H 7D 7200
a 30 IN A 192.0.2.1
b 60 IN A 192.0.2.2
c IN A 192.0.2.3
$TTL 1H
d 3600 IN A 192.0.2.4
e 30 IN A 192.0.2.5
```

Output (no bump):

```
$ORIGIN example.org.
$TTL 30
@    IN SOA ns hostmaster (
    2024041300 ; serial  Sat, 13 Apr 2024 #00
    4H         ; refresh
    1H         ; retry
    7D         ; expire
    7200       ; minimum
)
a    IN A   192.0.2.1
b 60 IN A   192.0.2.2
c    IN A   192.0.2.3
$TTL 1H
d    IN A   192.0.2.4
e 30 IN A   192.0.2.5
```

### 8.3 Inherited owner across a blank line

Input `$ORIGIN x.example.\na IN A 192.0.2.1\n\n IN AAAA 2001:db8::1\n`
formats as:

```
$ORIGIN x.example.
a IN A    192.0.2.1

a IN AAAA 2001:db8::1
```

### 8.4 Unix time serial

`@ IN SOA ns hostmaster 1282630067 4H 1H 7D 7200` under `$ORIGIN example.org.`
formats (no bump) with the line
`    1282630067 ; serial  Tue, 24 Aug 2010 06:07:47 UTC`. With a bump the
serial becomes the current Unix time (or `1282630068` if the clock is not
past it).

### 8.5 NewRecord

| owner | ttl | type | rdata | written (plain) |
|---|---|---|---|---|
| `www` | 0 | A | `192.0.2.1` | `www IN A 192.0.2.1` |
| `www` | 300 | AAAA | `2001:db8::1` | `www 300 IN AAAA 2001:db8::1` |
| `@` | 0 | MX | `10   mx.example.org.` | `@ IN MX 10 mx.example.org.` |
| `@` | 0 | CAA | `0 issue "ca.example.net; validationmethods=dns-01"` | `@ IN CAA 0 issue "ca.example.net; validationmethods=dns-01"` |
| `_acme-challenge` | 0 | TXT | `tok"en\x` | `_acme-challenge IN TXT "tok\"en\\x"` |
| `txt` | 0 | TXT | `with spaces ; not a comment` | `txt IN TXT "with spaces ; not a comment"` |

Rejected (error wrapping `ErrInvalidRecord`): rdata `192.0.2.1\nevil IN A
192.0.2.66`; `192.0.2.1 ; evil`; `192.0.2.1\n$INCLUDE /etc/passwd`;
`( 192.0.2.1 )`; CAA `0 issue "ca`; empty or blank rdata; rdata with NUL;
owner `evil IN A 192.0.2.66\nwww`; owner `a b`; empty owner; owner `"www"`;
type 65280 (not in table). TXT rdata `a\nb ; ( )` is accepted (it is quoted).

### 8.6 Equality

With `$TTL 60` in both lists, `www IN A 192.0.2.1` equals `www 60 IN A
192.0.2.1` and `www 1M IN A 192.0.2.1` under `EntriesEqual`, but not under
`Entry.Equal`; `www 120 IN A ...` equals neither; with `$TTL 60` on one side
and `$TTL 120` on the other the lists differ; `www 60 IN A ...` with no
`$TTL` does not equal `www IN A ...` with no `$TTL`.

### 8.7 Names

`Relative("www.example.org.", "example.org.")` is `www`;
`("example.org.", "example.org.")` is `@`; `("WWW.Example.ORG.",
"example.org.")` is `WWW`; `("other.org.", "example.org.")` and
`("myexample.org.", "example.org.")` are unchanged; `("www", "example.org.")`
is `www`; `("@", ...)` is `@`.

`Origin` cases: `$ORIGIN example.org.` + `@ IN SOA ...` gives
`example.org.`; `example.org. IN SOA ...` alone gives `example.org.`; `@ IN
SOA` with hint `example.org` gives `example.org.`; `$ORIGIN example.org.` +
`sub IN SOA` gives `sub.example.org.`; `$ORIGIN example.org.` + `www IN A`
(no SOA) gives `example.org.`; `www IN A` alone gives `""`; `@ IN SOA` alone
gives `""`.

### 8.8 Parse errors

Each of these must fail with a `*ParseError` naming the line: `a IN TXT
"unterminated`; `a IN TXT "ends with backslash\`; `@ IN SOA a b (1 2 3 4 5`
(unclosed); `)`; `$ORIGIN` alone; `$TTL\n`; `a IN NS b\x00c`; `a IN A
1\rb IN A 2\n` (lone CR); `a IN A 1 ; c\n IN` (missing type); `a 1 2 IN A
x` (double TTL); `a IN IN A x` (double class).

`a IN TXT "\1x" "\999" "\0650"` parses with decoded values `1x`, `999`,
`A0` (a malformed `\DDD` escapes only its first character).

## 9. Testing requirements

- Unit tests for every section 8 example, byte-exact.
- Property tests (`testing/quick` or hand-rolled loops) on generated zones:
  `Format` is idempotent; `Reformat(text)` equals `Format(ResolveOwners
  (Parse(text)))`; `Verify(apex, WritePlain(e), Format(e))` passes for every
  parsed file; `NewRecord` output parses back to an entry `Equal` to itself.
- A `FuzzParse` target: `Parse` never panics; when it succeeds, `Format`
  succeeds and `Verify` passes for inputs the reference parser accepts.
- Golden files under `testdata/` for `Reformat`: input and expected output
  pairs, with a `-update` flag to regenerate.
- Coverage of the package at or above 90 percent.

## 10. Integration into zoneomatic (separate step, after the module exists)

zoneomatic currently uses `pkg/zonefile` through: `Load`, `Apex`,
`ResolveOwners`, `NewRecord`, `EntriesEqual`, `Entry.Equal`, `Format`,
`WritePlain`, `Verify`, `Records`, `Comments`, `NameEqual`, `RelativeName`,
`AbsName`, `Fqdn`, `StringToTTL`, `Quote`, `UserComment`, and the entry
accessors `Domain`, `TTL`, `Class`, `Type`, `RRType`, `Values`,
`RawValues`, `ValuesStrings`, `Comments`, `IsComment`, `IsControl`,
`IsBlank`, `Command`, `WithComments`, `SetDomain`. The integration session
replaces these with the `masterfile` API, deletes `pkg/zonefile`, rewrites
`cmd/dnsfmt` as `cmd/mfmt` over `Reformat` (section 6.9; the binary name
`dnsfmt` may stay as an alias of `mfmt` in goreleaser), removes the two
inherited license files, and runs zoneomatic's
golden tests: their expected files must still match byte for byte except for
the date-serial comment form, which this specification changes (section
6.6; zoneomatic's goldens use Unix time serials, so none should change).

`WithComments(comments)` appends comments to an entry's last line as one
joined comment; `SetDomain(name)` replaces or clears the owner. Both are
needed by zoneomatic's update logic and belong in the new module as entry
methods (`WithComments`, `WithOwner`).

## 11. Open decisions for the implementer

Record them in `docs/DESIGN.md`:

- whether the lexer is a hand-written state function or a byte loop; the
  only constraints are sections 3 and 6.1;
- how comments are attached to fields internally, as long as section 5 is
  reachable and section 6.5 places them;
- whether `Entry` is a struct with exported fields or an opaque type with
  accessors.
