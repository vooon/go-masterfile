# Design notes

Decisions taken while implementing `docs/spec.md`, in particular the open
points of its section 11 and everything the spec leaves to the implementer.
The spec remains authoritative; this file records how its gaps were filled
and where behaviour was pinned down.

## Lexer and parser

- **Hand-written byte loop** (`lex.go`), not a state-function lexer. The
  lexer owns line counting and the parenthesis group state, because line
  terminators inside a group are blanks and that is a lexical fact. It
  returns one token at a time; the parser gathers tokens up to the next
  newline token into one entry.
- **Owner presence** is decided by the first token's column: an item at
  column 1 is the owner; anything else means the owner is inherited.
- **Comment attachment**: comments are attached by position while fields
  are collected. A comment before the first field goes to `head`, a comment
  after field *n* goes to field *n*, and comments after the last field move
  to `tail`, so `Field.Comments` is non-empty only for fields followed by
  another field. A record with no rdata keeps all its comments in `tail`
  so it still formats on one line.
- **Malformed escapes**: `\DDD` with a value above 255, or fewer than three
  digits, escapes only the next byte (spec 8.8). The reference parser
  (miekg/dns) instead wraps the value into one byte. Formatting re-quotes
  TXT strings from the decoded value, so such an input yields a formatted
  file the reference parser reads differently and `Verify` refuses the
  write. That is the intended safe outcome for a file that BIND would reject
  anyway; the fuzz target skips these inputs. A backslash directly before a
  line terminator or the end of input is an error in items as well as in
  quoted strings.
- **Directives** are recognised at any column (BIND requires column 1, but
  nothing is gained by failing). Every directive needs at least one
  argument; `$TTL`'s argument must parse as a TTL. `$INCLUDE` and
  `$GENERATE` arguments are kept as written. Directive arguments may carry
  comments like record fields.
- **Class before type**: `ANY` and `NONE` are both class names and entries
  in the type table; the class check wins, so `a IN ANY ...` is a "double
  class" error, which is right for zone files.
- **Type names** are canonicalised to upper case; `TYPE<n>` keeps that
  spelling even when *n* is a known type (equality compares the number).
- **Trailing blank lines** are kept as one `Blank` entry by the parser; the
  formatter drops leading and trailing blanks and collapses runs. Parsing
  therefore loses nothing a human can see; writing normalises.

## Data model

- **`Entry` is opaque** with accessor methods. This is what makes "copies
  never alias" true without deep-copying on every assignment: nothing in the
  package mutates an entry's slices after construction, `WithComments` and
  `WithOwner` return new values, and accessors that expose slices
  (`Fields`, `Args`, `Head`, `Tail`, `Comments`, `Values`, `RawValues`)
  return fresh copies. Owner resolution in `Parse` only assigns the owner
  string.
- **TTL** is stored as a value plus a `hasTTL` flag; `Entry.TTL()` returns
  `(TTL, bool)` rather than a pointer, so no caller can reach inside.
- **`Zone` is the one type** a caller touches: `Parse` and `New` build it,
  its `Entries` are open for ranging and splicing, the operations and the
  writers are methods. `Zone.Records()` is a range-over-func iterator
  yielding index and entry, so callers can find a record and then splice
  `Zone.Entries`.
- **`Zone.Changed` is a flag**, not a diff against a baseline: operations
  set it when `EntriesEqual` says the meaning changed, hand edits set it
  explicitly, `Commit` reads it. Cheaper than keeping a copy, and honest
  about hand edits the library cannot see.
- **`Parse` always resolves owners.** There is no half-parsed state: the
  apex comes from the caller's argument, the SOA, the first `$ORIGIN` or
  the root, in that order of trust, and a caller's argument that
  contradicts the SOA is an error rather than a silent choice.
  `Zone.Check` is the separate, opt-in gate for "serveable on its own"
  (origin known, SOA present), so `$INCLUDE` fragments remain first-class.

## Names

- `Relative` under the root origin `.` strips the trailing dot of every
  absolute name (`www.` becomes `www`, `.` becomes `@`) unless another dot
  would remain (`..` stays, so repeated formatting cannot erode a name). `Parse` falls
  back to `.` when no apex is known, and this rule keeps origin-less files
  such as `www IN A ...` byte-stable instead of turning them into `www.`.
- `Absolute("@", "")` is `""`, but `Parse` never resolves against an empty
  origin: with the root fallback `@` stays `@`, and `Check` reports the
  missing origin to callers that need one.
- Resolution and display start from the same origin, the caller's hint or
  the root, which the `Zone` remembers; neither starts from the apex that
  was found. Otherwise a file without `$ORIGIN` whose SOA owner is `0`
  would resolve that record to `0.0.` (fuzz-found), and a record written
  before a late `$ORIGIN` would be rewritten with a trailing dot. The
  price is that re-parsing such a file *with* its found apex as the hint
  reads its relative names differently; that is the file's ambiguity, not
  the formatter's, and the tests re-parse with the hint they started with.
- `NameEqual` is literal apart from ASCII case: `www` and `www.` differ.
  Normalisation is the caller's job via `Fqdn`/`Absolute`.

## Internationalised names

- `ToASCII` and `ToUnicode` (`idna.go`) convert between U-labels and
  A-labels with `golang.org/x/net/idna`, which was already in the module
  graph through miekg/dns, so no new dependency is added.
- Conversion is **per label**, splitting on unescaped dots, and only labels
  that contain bytes above 0x7F (`ToASCII`) or start with `xn--`
  (`ToUnicode`) are touched. Everything else is copied byte for byte, so
  `@`, `*`, `_acme-challenge`, ASCII upper case and escapes survive. A
  whole-name IDNA profile would reject or rewrite those.
- The profile is the lenient lookup mapping with the LDH label check off,
  not the strict registration profile: a zone file editor must accept what
  people already have in their zones.
- Nothing in the package converts implicitly. Zone files hold A-labels and
  `NameEqual`, `Relative` and `NewRecord` stay byte-oriented as the spec
  requires; callers convert at their input and display boundaries.

## Editing operations (edit spec sections 2, 3, 5)

- Operations are values (`Replace`, `Insert`, `Delete`, `DeleteOwner`,
  `AddRemove`, `Collapse`) with an unexported `apply`; `Zone.Apply` is the
  only mutator. It works on a shallow copy of the zone and installs the
  result at the end, so a failing operation anywhere in the list leaves
  the zone untouched. Every operation builds a new entry slice rather than
  editing in place, which is what makes that copy safe to share.
- Records inside operations are `RR{Type, TTL, Content}` data. `Apply`
  builds entries with `NewRecord` under the operation's owner, respelled
  to the owner the zone already uses when it has matching records (spec
  6.2 wants `loop` even when the client said `LOOP.at.example.com.`).
- Owners are normalised once per call (`Zone.owner`): trimmed, made
  absolute against the apex, checked with `InZone`, then made
  apex-relative with `Relative`. Anchors go through the same check, so an
  anchor outside the zone is `ErrNotInZone` too rather than silently
  matching nothing. Matching compares owners through `relOwner`, so
  entries appended by hand with absolute owners are found as well.
- Content matching uses `Entry.Content` on the record side and
  `normalizeContent` on the client side, per record type: a selector with
  several types normalises each candidate against the type of the entry it
  is compared with. For non-text types the client string is tokenised with
  the zone lexer and its decoded fields joined by one space, so
  `0 issue "ca.example"` matches a CAA record whose `Content` is
  `0 issue ca.example` (spec 6.3). Collapsing whitespace is the fallback
  for strings that do not tokenise.
- Placement never splits an owner's block: after the last anchor match the
  insertion point moves past following records with the same owner. The
  spec's examples are unaffected (their anchors match whole blocks); the
  rule matters for the `Type` anchor, which otherwise would put a new host
  between an existing host's A and AAAA.
- `DefaultPlacement` encodes how the fixtures are laid out by hand: own
  block, then same first label, then same parent, then same type. `Insert`
  uses it; `Replace` keeps the explicit placement the spec's examples pin
  down (a new name with no anchors goes to the end).
- Carried comments (spec 2.7) are attached with `WithComments`, which joins
  them into one trailing comment; the original texts remain as substrings,
  which is what `Verify` checks.
- `Result.Index` is the index in `Entries` after the operation, so callers
  can look at what was inserted.
- `Serial` reads the first SOA's third field; a non-numeric or overflowing
  serial reports false rather than 0.

## Zone routing and reverse names (edit spec section 4)

- `InZone` and `Relative` share one label-boundary check (`underOrigin`),
  so "is this name in that zone" and "what is its relative form" can never
  disagree. The root apex `.` contains everything.
- `LongestZone` counts labels with the same escape-aware splitter used by
  the IDNA helpers (`labels`, an iterator), so `a\.b.example.` has two
  labels under `example.`.
- Reverse names are built from `netip.Addr` and parsed back strictly: octet
  labels must be plain decimals 0..255 with no leading zeros, nibble labels
  one hex digit in either case, and the arpa suffix is matched
  case-insensitively with or without the trailing dot. `ReversePrefix`
  accepts one to four octets or one to 32 nibbles and nothing else, which
  excludes RFC 2317 classless labels by construction.
- `IsReverseZone` requires at least one label before `in-addr.arpa.` or
  `ip6.arpa.`, following the spec's "ends in" wording; the arpa domains
  themselves are not reverse zones.

## Equality

- `Entry.Equal` compares decoded values, so `"a b"` and `a\ b` in a TXT are
  equal, and compares explicit TTLs by seconds (`60` equals `1M`). An absent
  class equals `IN`.
- Directives compare by meaning: `$TTL` by seconds, `$ORIGIN` by name,
  others by decoded arguments.

## Formatting

- The first pass (`plan`) computes displayed owners, blanked repeats,
  dropped TTLs and column widths; the second pass writes. Owner comparison
  for blanking uses the displayed form under the `$ORIGIN` in force.
- A kept TTL is always written as decimal seconds (spec 6.5 rule 2), so a
  record TTL of `1h` that differs from `$TTL` is written `3600`; the
  directive's own argument stays as written.
- Multi-line generic records put `tail` comments on the last field's line;
  the closing `)` is always alone. The alignment width counts only fields
  that carry a comment.
- SOA: comments after `(`, after MNAME and after RNAME are all joined on the
  first line. A non-numeric serial gets the bare comment `; serial` plus any
  user text. Only the first SOA in the entry list is bumped.
- Long keys: the check runs before the generic multi-line decision, and all
  comments of such a record land on its first line. Exactly 55 bytes of
  data stays on one line; 56 splits.
- `Format` with no entries writes nothing (no final LF for an empty file).
- Write errors: output goes through a `bufio.Writer`, whose first error
  sticks and is returned from `Flush`.

## Verification

- `Records` passes `.` to the reference parser when the apex is empty,
  because miekg/dns cannot resolve relative names against an empty origin.
  Records without a TTL and without `$TTL` get TTL 0 from miekg/dns; both
  sides see the same, so it does not matter for the comparison.
- A user comment is "found" in the formatted text when it is a substring of
  any comment there, because the serial comment is regenerated around it.
- **Known reference-parser quirk** (miekg/dns v1.1.73, `scan.go`): when a
  comment inside parentheses ends, the lexer resets its "RR type seen"
  flag, so a later bare (unquoted) field that spells a type name, such as
  a 55-byte key piece that happens to be `A` or `MX`, or an HINFO field
  `A`, is tagged as a type and the record is rejected ("bad DNSKEY
  PublicKey"). BIND accepts the same text. Such a formatted file fails
  `Verify` and the write is refused, which is the safe outcome; the fuzz
  target skips this shape. The fix belongs upstream.

## Command

`mfmt` lives in zoneomatic (spec 6.9); this module ships `Reformat` for it
and nothing else, so the library's dependency list stays at miekg/dns.
