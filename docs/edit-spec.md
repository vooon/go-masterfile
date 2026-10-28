# masterfile: specification for the zone editing operations

Status: draft, companion to `docs/spec.md` (the "core spec"). Target: the
`masterfile` package itself (not a subpackage: the library's purpose is
read, modify, format, verify, write, and callers should not need two imports
for that), Apache-2.0, taking over the record-editing logic now living in
zoneomatic's `internal/zone`. Where this document says "the package", it
means `masterfile`; "core" refers to the functions already specified in
`docs/spec.md`. Delivery order: section 4 (routing and reverse-zone
helpers) first, then the operations.

## 0. Ground rules

- The operations depend only on the core functions, the standard library
  and `github.com/miekg/dns` (for type name tables). No I/O, no logging, no
  tracing, no `context.Context`, no goroutines. It transforms
  entry lists and reports what it did; the caller writes files and logs.
- Unlike the parser, this logic was written for zoneomatic under Apache-2.0,
  so the existing code in `internal/zone/controller.go` and `pdns.go` may be
  read and ported. It must be ported to the core spec's entry type and
  adjusted where this document says the behaviour changes.
- Every operation is a pure function of its inputs: same entries and same
  arguments give the same result, and the input slice is never modified.
  Entries are values (core spec section 5).
- The golden tests in zoneomatic's `internal/zone/testdata` describe the
  expected results; they move into this package's `testdata/` with the
  operations they test.

## 1. Purpose

zoneomatic receives small intents from clients: "the address of `host` is
now X", "present this ACME token", "replace this RRset", "add this value",
"point this reverse name at that host". Each intent becomes a change to one
zone file that must:

- touch only the records the intent is about, and keep every other entry,
  comment and blank line where it was;
- place new records where a human would put them (next to related records,
  not always at the end);
- not lose comments attached to records it replaces;
- be a no-op, with no file write and no serial bump, when the zone already
  says what the intent says;
- produce the file bytes through the core's format-and-verify path.

## 2. Model

### 2.1 Zone and operations

The core `Zone` (core spec section 5) is the editing session: `Parse(data,
apex)` builds it with owners resolved and the apex checked
(`ErrApexMismatch`), `New(apex)` builds an empty one. zoneomatic requires a
served file to have an origin and an SOA; `(*Zone).Check()` enforces that
after parsing (`ErrNoOrigin`, `ErrNoSOA`), while `$INCLUDE` fragments skip
it. `(*Zone).Apex()` returns the absolute apex.

Operations are values implementing `Op`, applied with

```go
func (z *Zone) Apply(ops ...Op) ([]Result, error)
```

in order and atomically: when an operation fails, the error names it and the
zone is left exactly as it was. Each returns a `Result`:

```go
type Result struct {
    Matched  int  // entries the selector matched
    Removed  int  // entries dropped
    Inserted int  // entries added
    Index    int  // position of the first inserted entry, -1 if none
    Changed  bool // the zone's meaning changed
}
```

Records travel inside operations as data, not entries:

```go
type RR struct {
    Type    uint16
    TTL     uint32 // 0: no explicit TTL
    Content string // 2.4
}
```

`Apply` builds them with core `NewRecord` (owner from the operation), so
the security boundary holds and an operation can be logged or marshalled.
Operations never write anything. The caller decides when to call `Commit`.

### 2.2 Changed and Commit

```go
z.Changed // field
func (z *Zone) Commit(bumpSerial bool) (data []byte, changed bool, err error)
```

`Zone.Changed` is a flag: every operation compares the entries before and
after with core `EntriesEqual` and sets it when they differ in meaning
(`Result.Changed` reports the same per operation); code that edits
`Entries` by hand sets it itself. `Commit` returns `changed == false` and
`data == nil` while the flag is false. Otherwise it writes the entries with
core `WritePlain` and `Format` (bumping the serial when asked), runs core
`Verify` on the pair, and returns the formatted bytes. A `Verify` failure
is returned as is (it wraps `ErrUnsafeWrite`) and nothing else is returned:
the caller must not write. `Commit` leaves the flag alone: a `Zone` is one
read-modify-write cycle.

### 2.3 Names

Owners passed to operations are **absolute or apex-relative**, as a client
would send them (`www`, `www.example.org.`, `@`, `example.org.`). An owner
outside the zone (`other.org.`, `www.example.net.`) is `ErrNotInZone`. The
package normalises them to the apex-relative form of the core spec before
matching, so `WWW.Example.ORG.` and `www` select the same records. The
comparison is core `NameEqual`.

`(*Zone).AbsoluteOwner(e Entry) string` gives an entry's absolute owner.

### 2.4 Content

A record's **content** is core `Content()`: TXT/SPF strings concatenated,
other fields joined by one space. A content string given by a client is
normalised the same way: for TXT/SPF it is taken as is; for other types it
is tokenised like rdata and its decoded fields joined by one space (so
quoting and spacing do not matter; a string that does not tokenise only has
its whitespace runs collapsed). All value matching
in this package compares contents, nowhere raw fields. (zoneomatic currently
matches PTR targets and ACME tokens byte for byte and other values by
content; this unifies them.)

### 2.5 Selector

```go
type Selector struct {
    Owner    string   // see 2.3; "" means any owner (queries only)
    Types    []uint16 // nil: any type
    Contents []string // nil: any content; else content must be in the list
}
```

A selector matches a Record entry whose owner equals `Owner`, whose type is
in `Types` (or any), and whose content is in `Contents` (or any). Blank,
Comment and Directive entries never match. An empty `Owner` matches any
owner; the editing operations (`Replace`, `Delete`, `AddRemove`) reject it
with `ErrNotInZone`, the queries (`Select`, `Owners`) accept it.

### 2.6 Placement

Where new records go when nothing was there to replace:

```go
type Anchor struct {
    Owner  string // records with this owner (2.3)
    Prefix string // records whose relative owner starts with this label prefix, case-insensitive
    Under  string // records whose owner is this name or below it (2.3)
    Type   uint16 // records of this type
}

type Placement []Anchor
```

Conditions set in one anchor must all hold. Anchors are tried in order. The
first anchor that matches any Record entry decides: new records are
inserted right after the **last** matching entry and after the records
that follow it with the same owner, so an owner's block (an A/AAAA pair) is
never split. If no anchor matches, or `Placement` is empty, new records are
appended at the end. Only Record entries count; a comment or blank line
after the last matching record stays below the inserted records.

Example from zoneomatic: ACME records use
`Placement{{Owner: name}, {Prefix: "_acme-challenge."}}`: next to the same
name if it has records, else after the last challenge record in the file,
else at the end.

`(*Zone).DefaultPlacement(owner string, rtype uint16) Placement` is the
list a human would use: the owner's own records; else the records whose
first label is the same (`{Prefix: "_acme-challenge."}` for
`_acme-challenge.zot`); else the records under the same parent (siblings:
`{Under: "zot"}`); else the last record of the same type; else the end.
`Insert` (3.6) uses it when given no placement.

The type anchor is for hosts, where "the other A records" is a meaningful
neighbourhood. An owner whose first label starts with `_` is an attribute
leaf (RFC 8552: `_acme-challenge`, `_dmarc`, `_25._tcp`) and gets no type
anchor: TXT, SRV and TLSA records of unrelated services share a type without
belonging together, and the first challenge record of a zone must not be
filed into whatever commented section holds the last TXT. It goes to the end
unless its label family or parent is present.

### 2.7 Carried comments

When an operation drops a Record entry while inserting others in its place,
the dropped entries' comments (all of them, in file order) are appended to
the first inserted record's trailing comments. When an operation drops
records and inserts nothing, the comments are dropped with them.

## 3. Operations

All owners are checked per 2.3 first (`ErrNotInZone`). Records are `RR`
values (2.1) built with core `NewRecord` under the operation's owner, in
the spelling the zone already uses for that owner when it has records.

### 3.1 Replace

```go
type ReplaceMode int
const (
    ReplaceAll   ReplaceMode = iota // every match goes, records take the first match's place
    ReplaceFirst                    // only the first match goes, later matches stay
)

type Replace struct {
    Selector
    Records   []RR
    Mode      ReplaceMode
    MustExist bool      // no match: ErrNotFound instead of inserting
    Placement Placement // where to insert when nothing matched
}
```

Walk the entries once. The first entry matching `Selector` is replaced by
`Records` (zero or more). Every later match is dropped (`ReplaceAll`) or kept
(`ReplaceFirst`). Comments of dropped matches are carried (2.7). If nothing
matched: with `MustExist` return `ErrNotFound` and change nothing; otherwise
insert `Records` per `Placement`. Empty `Records` and no match is a no-op
without error (a delete of something absent).

The `Changed` outcome follows from entry equality: replacing `www IN A
192.0.2.1` with an identical record is not a change, and no serial bump
happens.

### 3.2 Delete

```go
type Delete struct{ Selector }
```

`Replace{Selector: sel, Mode: ReplaceAll}` with no records. Absent is a
no-op.

### 3.3 DeleteOwner

```go
type DeleteOwner struct{ Owner string }
```

Drops every Record entry with that owner, any type. Comments go with them.

### 3.4 AddRemove

```go
type AddRemove struct {
    Owner     string
    Type      uint16
    TTL       uint32   // for added records; 0: no explicit TTL
    Add       []string // contents
    Remove    []string // contents
    Placement Placement
}
```

Edits one RRset in place, as DNS UPDATE does (RFC 2136):

1. every entry of the set (owner and type) whose content is in `Remove` is
   dropped;
2. of the remaining set, the contents are collected; each content of `Add`
   that is already present, or duplicates an earlier one, is skipped;
3. the surviving `Add` contents are inserted as records right after the
   last remaining entry of the set; if the set is now empty, per
   `Placement`.

Adding a present value and removing an absent one are no-ops. `Add` is
processed after `Remove`, so a value both removed and added ends up present
once, at the position rule of step 3.

### 3.5 Collapse

```go
type Collapse struct {
    Owner     string
    Type      uint16
    Drop      []string // contents
    Keep      string   // content
    KeepTTL   uint32   // 0: no explicit TTL
    Placement Placement
}
```

Leaves the set in a state with exactly one record of content `Keep` and no
record of a content in `Drop`, used by zoneomatic's ACME cleanup (the
`Keep` record is the placeholder):

1. entries of the set with content in `Drop` are removed;
2. entries of the set with content equal to `Keep`: the first stays, later
   ones are removed;
3. if none stayed, a `Keep` record is inserted at the position of the first
   entry removed in step 1, else per `Placement`;
4. comments of all removed entries are carried onto the entry that stayed or
   was inserted.

Entries of the set with other contents are untouched.

### 3.6 Insert

```go
type Insert struct {
    Owner     string
    Records   []RR
    Placement Placement // empty: DefaultPlacement(Owner, Records[0].Type)
}
```

Adds the records the zone does not already hold (same owner, type and
content; those it holds count as `Matched`) where a human would put them
(2.6). Nothing else is touched; no records is a no-op.

### 3.7 Queries

```go
func (z *Zone) Select(sel Selector) []Entry              // in file order, copies
func (z *Zone) Owners(sel Selector) []string             // absolute owners of matches, deduplicated, file order
func (z *Zone) RRSets() []RRSet
func (z *Zone) Serial() (uint32, bool)
func (z *Zone) SOA() (Entry, bool)

type RRSet struct {
    Owner    string   // absolute
    Type     string   // upper-case
    TTL      uint32   // effective TTL of the first record, 0 when unknown
    Contents []string // in file order
}
```

`RRSets` groups Record entries by (owner, type) in order of first
appearance, with the `$TTL` in force applied for records without an explicit
TTL. `Serial` parses the SOA's third field.

## 4. Routing and reverse-zone helpers

Package-level functions, no `Zone` needed. They let the caller pick the zone
for a name and build reverse names without touching miekg/dns itself.

```go
func InZone(name, apex string) bool
func LongestZone(name string, apexes []string) (apex string, ok bool)
func ReverseName(addr netip.Addr) string
func ReverseAddr(name string) (netip.Addr, bool)
func IsReverseZone(apex string) bool
func ReversePrefix(apex string) (netip.Prefix, bool)
```

- `InZone`: `name` equals `apex` or ends with `"." + apex`, both as absolute
  names, compared with core `NameEqual` on the suffix at a label boundary.
  `www.example.org.` is in `example.org.`; `myexample.org.` is not.
- `LongestZone`: the apex in `apexes` that contains `name` and has the most
  labels; `ok` false when none does. Ties cannot occur between distinct
  apexes that both contain a name.
- `ReverseName`: `192.0.2.1` gives `1.2.0.192.in-addr.arpa.`; `2001:db8::1`
  gives the 32 reversed nibbles under `ip6.arpa.`. A 4-in-6 mapped address
  is unmapped first. The result is absolute.
- `ReverseAddr`: the inverse for a full reverse name (4 octets or 32
  nibbles); anything else gives `ok` false.
- `IsReverseZone`: apex ends in `.in-addr.arpa.` or `.ip6.arpa.`
  (case-insensitive, absolute form).
- `ReversePrefix`: `3.2.1.in-addr.arpa.` gives `1.2.3.0/24`; one to four
  octet labels give /8 to /32; `8.b.d.0.1.0.0.2.ip6.arpa.` gives
  `2001:db8::/32`, one to 32 nibble labels give /4 to /128. RFC 2317
  classless names (`0/25.2.0.192.in-addr.arpa.`) and anything else give `ok`
  false.

## 5. Errors

| Error | When |
|---|---|
| `ErrNoOrigin` | `Check`: the apex is only the root fallback |
| `ErrNoSOA` | `Check`: no SOA record |
| `ErrApexMismatch` | `Parse`: SOA owner differs from the given apex |
| `ErrNotInZone` | `Apply`: an owner or anchor outside the apex |
| `ErrNotFound` | `Apply`: `Replace` with `MustExist` and no match |
| `ErrInvalidRecord` | `Apply`: an `RR` that `NewRecord` rejects |
| core `ErrUnsafeWrite` | `Commit`: verification failed |
| core `*ParseError` | `Parse`: syntax |

`Apply` fails as a whole: a failing operation leaves the zone untouched.

## 6. Examples (normative)

Inputs are zoneomatic's fixtures. In this repository's `testdata/edit/`
they carry documentation addresses instead (`192.0.2.0/24`, `2001:db8::/32`,
reverse zone `2.0.192.in-addr.arpa.`); the layouts below are otherwise what
the goldens hold. Outputs below are
`Commit(true)` results in a test where the clock gives serial `1763822926`
(one above the fixture's). The serial comment follows the core spec. Calls
are written in shorthand: `Replace({selector}, [records], {options})`
stands for `Apply(Replace{Selector: ..., Records: ..., ...})`, and records
such as `4 IN PTR new.example.com.` for `RR{Type: PTR, Content:
"new.example.com."}` under the operation's owner.

### 6.1 Reverse zone fixture

```
$ORIGIN 3.2.1.in-addr.arpa.
$TTL 60
; SOA Record
@                                 IN   SOA        ns1.example.com. hostmaster.example.com. (
                                                     1763822925   ; serial  Sat, 22 Nov 2025 14:48:45 UTC
                                                     1H           ; refresh
                                                     600          ; retry
                                                     1W           ; expire
                                                     1D           ; minimum
                                                     )

; NS Records
@                                 IN   NS         ns1.example.com.
@                                 IN   NS         ns2.example.com.

; PTR records
1                                 IN   PTR        router.example.com.
4                                 IN   PTR        hub.example.com.
4                                 IN   PTR        legacy.example.com.
```

All four results share this head, which also shows that repeated `@` owners
collapse and the SOA is re-laid out:

```
$ORIGIN 3.2.1.in-addr.arpa.
$TTL 60
; SOA Record
@ IN SOA ns1.example.com. hostmaster.example.com. (
    1763822926 ; serial  Sat, 22 Nov 2025 14:48:46 UTC
    1H         ; refresh
    600        ; retry
    1W         ; expire
    1D         ; minimum
)

; NS Records
@ IN NS  ns1.example.com.
  IN NS  ns2.example.com.

; PTR records
1 IN PTR router.example.com.
```

Tails, each after the head:

**append** — `Replace({Owner:"4", Types:[PTR], Contents:["new.example.com."]},
[4 IN PTR new.example.com.], {Mode: ReplaceAll, Placement: [{Owner:"4"}]})`:

```
4 IN PTR hub.example.com.
  IN PTR legacy.example.com.
  IN PTR new.example.com.
```

The same call with `hub.example.com.` matches, replaces like with like, and
`Changed` is false.

**replace** — `Replace({Owner:"4", Types:[PTR]}, [4 IN PTR
rebooted.example.com.], {Mode: ReplaceFirst})`:

```
4 IN PTR rebooted.example.com.
  IN PTR legacy.example.com.
```

**replace-all** — same selector, `clean.example.com.`, `Mode: ReplaceAll`:

```
4 IN PTR clean.example.com.
```

**create** — `Replace({Owner:"5", Types:[PTR]}, [5 IN PTR five.example.com.],
{Mode: ReplaceAll, Placement: [{Owner:"5"}]})`: nothing matches, no anchor
matches, so it is appended:

```
4 IN PTR hub.example.com.
  IN PTR legacy.example.com.
5 IN PTR five.example.com.
```

### 6.2 Forward zone fixture

```
$ORIGIN at.example.com.
$TTL 60
; SOA Record
@                                 IN   SOA        ns1.example.com. hostmaster.example.com. (
                                                     1763822925   ; serial  Sat, 22 Nov 2025 14:48:45 UTC
                                                     1H           ; refresh
                                                     600          ; retry
                                                     1W           ; expire
                                                     1D           ; minimum
                                                     )

; NS Records
@                                 IN   NS         ns1.example.com.
                                  IN   NS         ns2.example.com.

; Existing record
loop                              IN   A          127.0.0.1
                                  IN   AAAA       ::1

; sub-domain challenge
_acme-challenge.zot               IN   TXT        "8NwtedqEdkceTHTZILXsMU2UWEeEon24tXw0dSSDkrs"
```

**DDNS, new name** — `Replace({Owner:"new-entry", Types:[A, AAAA]},
[new-entry IN A 1.2.3.4, new-entry IN AAAA 2001:dead:beef::1], {Mode:
ReplaceAll})` appends both at the end:

```
...
; sub-domain challenge
_acme-challenge.zot IN TXT  "8NwtedqEdkceTHTZILXsMU2UWEeEon24tXw0dSSDkrs"
new-entry           IN A    1.2.3.4
                    IN AAAA 2001:dead:beef::1
```

The owner column becomes 19 wide (`_acme-challenge.zot`) and the type column
4 (`AAAA`), as the core spec requires.

**DDNS, existing name, v4 only** — `Replace({Owner:"loop", Types:[A]}, [loop
IN A 10.0.0.1], ReplaceAll)` changes the `A` line only; the `AAAA` record
stays as the second line of the pair. With both types in `Types` and both
records given, the first match (the `A` line) takes both records and the old
`AAAA` line is dropped, so the pair stays together in A, AAAA order.

**ACME present, apex name** — `Replace({Owner:"_acme-challenge",
Types:[TXT]}, [_acme-challenge IN TXT "fake/XKo9kaBlVnj9q0XWAWdoSYEPCOrhiZk3ztoBHx5c3O6X"],
{Mode: ReplaceAll, Placement: [{Owner:"_acme-challenge"}, {Prefix:
"_acme-challenge."}]})`: no record of that name exists, the prefix anchor
matches `_acme-challenge.zot`, so:

```
; sub-domain challenge
_acme-challenge.zot IN TXT  "8NwtedqEdkceTHTZILXsMU2UWEeEon24tXw0dSSDkrs"
_acme-challenge     IN TXT  "fake/XKo9kaBlVnj9q0XWAWdoSYEPCOrhiZk3ztoBHx5c3O6X"
```

With the core spec's TTL rule, a record built with TTL 60 gives the identical
file, since `$TTL 60` is in force.

**ACME present, two tokens (wildcard flow)** on a fixture that ends with
`_acme-challenge IN TXT "placeholder"`: first `Replace({Owner, [TXT],
Contents:["placeholder"]}, [token1], ReplaceAll, same Placement)` swaps the
placeholder; then the same call with `token2` matches nothing (the
placeholder is gone), the owner anchor matches the token1 line, and token2
lands right after it:

```
_acme-challenge.zot IN TXT  "8NwtedqEdkceTHTZILXsMU2UWEeEon24tXw0dSSDkrs"
_acme-challenge     IN TXT  "fake/token1-helloworld"
                    IN TXT  "fake/token2-helloworld"
```

**ACME cleanup** — `Collapse("_acme-challenge", TXT, drop:["fake/token2-helloworld"],
keep: _acme-challenge IN TXT "placeholder", same Placement)` on the file
above removes token2 and, as no placeholder exists, inserts it where token2
was; a second `Collapse` with `drop: [token1]` removes token1 and keeps the
one placeholder:

```
_acme-challenge.zot IN TXT  "8NwtedqEdkceTHTZILXsMU2UWEeEon24tXw0dSSDkrs"
_acme-challenge     IN TXT  "placeholder"
```

`Collapse` with a `drop` content that is absent and two placeholders present
leaves exactly one placeholder. `Collapse` on a name with no TXT at all
inserts the placeholder per `Placement`.

**ACME cleanup, sub name** — `Collapse("_acme-challenge.zot", TXT,
drop:["8NwtedqEdkceTHTZILXsMU2UWEeEon24tXw0dSSDkrs"], keep: placeholder)` on
the fixture gives a tail of

```
; sub-domain challenge
_acme-challenge.zot IN TXT  "placeholder"
```

**AddRemove** — on the fixture, `AddRemove("loop", A, [loop IN A 1.2.3.4],
nil, nil)` inserts after `loop IN A 127.0.0.1` (before the `AAAA` line); the
same call again reports `Changed` false. `AddRemove("loop", A, nil,
["127.0.0.1"], nil)` leaves only the `AAAA` line under `loop`; repeating it
is a no-op. On a zone where `_acme-challenge` has `tok-1` on an owner line
and `tok-2` on a continuation line, `AddRemove("_acme-challenge", TXT, nil,
["tok-2"], nil)` removes the continuation record: matching works on
resolved owners, not on what was written.

**DeleteOwner** — `DeleteOwner("loop")` removes the `A` and `AAAA` lines and
leaves the `; Existing record` comment and the blank line.

**MustExist** — `Replace({Owner:"nothere", Types:[A]}, [...], {MustExist:
true})` returns `ErrNotFound` and `Changed` stays false.

**Not in zone** — any operation with owner `www.example.net.` returns
`ErrNotInZone` before touching anything.

### 6.3 Content matching

| type | stored field(s) | client string | equal |
|---|---|---|---|
| MX | `10 mx.example.com.` | `10   mx.example.com.` | yes |
| MX | `10 mx.example.com.` | `20 mx.example.com.` | no |
| TXT | `"a b"` | `a b` | yes |
| TXT | `"a" "b"` | `ab` | yes |
| TXT | `"a b"` | `a  b` | no (TXT is taken as is) |
| CAA | `0 issue "ca.example"` | `0 issue "ca.example"` | yes |
| PTR | `host.example.com.` | `HOST.example.com.` | no (contents are exact; owners are not) |

### 6.4 Helpers

| call | result |
|---|---|
| `ReverseName(192.0.2.1)` | `1.2.0.192.in-addr.arpa.` |
| `ReverseName(2001:db8::1)` | `1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.` |
| `ReverseName(::ffff:192.0.2.1)` | `1.2.0.192.in-addr.arpa.` |
| `ReverseAddr("1.2.0.192.in-addr.arpa.")` | `192.0.2.1`, true |
| `ReverseAddr("2.0.192.in-addr.arpa.")` | false |
| `ReversePrefix("3.2.1.in-addr.arpa.")` | `1.2.3.0/24`, true |
| `ReversePrefix("8.b.d.0.1.0.0.2.ip6.arpa.")` | `2001:db8::/32`, true |
| `ReversePrefix("0/25.2.0.192.in-addr.arpa.")` | false |
| `IsReverseZone("3.2.1.IN-ADDR.ARPA")` | true |
| `InZone("www.example.org.", "example.org.")` | true |
| `InZone("myexample.org.", "example.org.")` | false |
| `LongestZone("a.b.example.org.", ["example.org.", "b.example.org.", "other.org."])` | `b.example.org.` |
| `LongestZone("example.net.", ["example.org."])` | false |

## 7. Testing requirements

- Byte-exact tests for every section 6 output, with the fixtures copied into
  `testdata/` and a `-update` flag for goldens.
- Idempotence: for every operation in section 6, applying it a second time
  to its own output leaves `Changed` false.
- Purity: the input `[]Entry` of each operation is unchanged afterwards
  (compare a deep copy).
- Property tests on generated zones: `Replace` followed by `Delete` of the
  same selector gives a zone whose `RRSets()` equal the original minus that
  set; `AddRemove(add)` then `AddRemove(remove)` of the same contents restores
  `RRSets()`; carried comments: every comment present before an operation is
  present after it unless the operation deleted records without inserting.
- Fuzz: `Parse` on arbitrary bytes never panics; a successful `Parse`
  followed by any operation with arbitrary owner/content strings never
  panics, and `Commit` either verifies or returns `ErrUnsafeWrite`.
- Atomicity: an `Apply` whose later operation fails leaves the zone as it
  was.
- Helpers: table tests for section 6.4, plus `ReverseAddr(ReverseName(a)) ==
  a` for random addresses.

## 8. Integration into zoneomatic

Each controller method becomes: lock, read file, `Parse(data, s.apex)` and
`Check()`, `Apply(ops...)`, `Commit(true)`, atomic write when `changed`,
log the `Result`s. The table uses the shorthand of section 6.
Tracing and slog stay in the controller. The mapping:

| zoneomatic | edit |
|---|---|
| `UpdateDDNSAddress(name, addrs)` | sort addrs; `records` = A per v4, AAAA per v6 (TTL 0); `Replace({name, Types: present types}, records, ReplaceAll)`; then PTR sync below |
| `UpdateACMEChallenge(name, new, old)`, new ≠ "" | `Replace({name, [TXT], Contents: old == "" ? nil : [old]}, [TXT new, acmeTTL], ReplaceAll, Placement[{Owner:name},{Prefix:"_acme-challenge."}])` |
| `UpdateACMEChallenge(name, "", old)` | `Collapse(name, TXT, [old], TXT "placeholder" acmeTTL, same Placement)` |
| `UpdateACMEChallenge(name, "", "")` | as present with new = "placeholder" |
| `ZMUpdateRecord(name, type, ttl, values)` | `Replace({name, [type]}, records, {ReplaceAll, MustExist})` |
| `ApplyRecordUpdate(name, type, ttl, add, remove)` | `AddRemove(name, type, records(add), remove, nil)` |
| `RemoveRecordName(name)` | `DeleteOwner(name)` |
| PDNS `ReplaceRRSet(name, type, ttl, values)` | `Replace({name, [type]}, records(ttl), ReplaceAll)` after the controller checks `ttl > 0` and `InZone` |
| PDNS `DeleteRRSet(name, type)` | `Delete({name, [type]})` |
| PDNS `Snapshot` | `RRSets()`, `Serial()`, NS contents of the apex set |
| `UpdatePTRAddress(rev, target, append)` | `Replace({rev, [PTR], [target]}, [PTR target], ReplaceAll, Placement[{Owner: rev}])` |
| `UpdatePTRAddress(rev, target, replace)` | `Replace({rev, [PTR]}, [PTR target], ReplaceFirst, Placement[{Owner: rev}])` |
| `UpdatePTRAddress(rev, target, replace-all)` | same with `ReplaceAll` |
| `DeletePTRRecord(rev, target)` | `Delete({rev, [PTR], [target]})` |
| `findPTRRecords(target)` | `Owners({Types: [PTR], Contents: [target]})` |
| `findZoneFile(name)` | `LongestZone(name, apexes)` |
| `isReverseZone`, `dns.ReverseAddr` | `IsReverseZone`, `ReverseName` |

Behaviour that changes with the port, to be noted in the zoneomatic
changelog:

- PTR target and ACME token matching become content-based (2.4); for these
  single-field types this only affects values written with different
  internal whitespace or quoting, which cannot occur.
- A `Replace` that matches records and inserts identical ones is a no-op
  (already true today through `EntriesEqual`).

After the port, `internal/zone` keeps: `Controller` interface, `DomainCtrl`
and `File` (locks, paths, options, OpenTelemetry, slog), `ValidACMEToken`,
`EmptyPlaceholder`, PTR orchestration across zones (`UpdatePTR`,
`removeStalePTR`, DDNS PTR sync), and the PDNS snapshot type. The golden
files move to the library; zoneomatic keeps end-to-end tests through the
controller against the same fixtures to prove the wiring.
