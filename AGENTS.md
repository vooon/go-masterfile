# AGENTS.md

Engineering notes for this repo: `masterfile`, a Go library for parsing,
editing and formatting DNS zone files (RFC 1035 "master files") that keeps
every comment and blank line a human put there. The authoritative spec is
`docs/spec.md`; read it before writing code.

## Source of truth
- `docs/spec.md` is the authoritative spec for parsing, formatting and
  verification; `docs/edit-spec.md` specifies the editing operations and
  the routing/reverse-zone helpers, all in the same package. Their example
  sections are normative: expected outputs are behavioural requirements,
  reproduced byte-exact.
- Open decisions (spec section 11) and anything the spec leaves unanswered
  are decided from the RFCs and the spec's intent, and recorded in `docs/DESIGN.md`.
- User instructions in chat override both unless they conflict with safety
  constraints.

## CRITICAL: clean-room mandate
This module is a new work written from the spec and the RFCs it cites.
- Do not open, read, copy or paraphrase zoneomatic's `pkg/zonefile` or
  `cmd/dnsfmt` (any revision), nor the upstream Go zone tokenizer library and
  zone formatting tool they descend from. Do not search for them, on disk or
  online.
- No code generation from other zone libraries.

## Dependencies
- The only third-party dependencies of the library are `github.com/miekg/dns`
  (type/class name tables, and the reference parser in `Verify`) and
  `golang.org/x/net` (IDNA, already required by miekg/dns). Tests use
  `github.com/stretchr/testify` (`require` for preconditions, `assert` for
  checks; expected value first). Do not add any other module; this library
  must stay cheap for zoneomatic to import.
- No command in this repo. The `mfmt` formatter (spec section 6.9) lives in
  zoneomatic as a thin wrapper over `Reformat`; this module only has to make
  `Reformat` sufficient for it.

## Public repo hygiene
This is a **public** repository. In tests, golden files, docs and examples
use only example domains (`example.org`, `example.net`, `lab.example`) and
RFC doc ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`,
`2001:db8::/32`). Never commit a real zone file, hostname, address or key
material.

## Architecture
- Module path `github.com/vooon/go-masterfile`, package `masterfile`. The
  name must not contain "zonefile" or "dnsfmt".
- Parsing is a plain function over a byte slice (no goroutines, no file I/O:
  the module never reads or writes files) and never panics (fuzz-tested).
- `Zone` is the one type callers touch. `Zone.Entries` is a flat list of
  `Blank | Comment | Directive | Record` entries holding raw and decoded
  field forms and comments in every position. Entries are values: copying
  one must not alias the original. `Zone.Changed` is an explicit flag.
- Pipeline: `Parse(data, apex)` (owners explicit and relative to the apex,
  so entries can be moved and compared; apex asserted) → `Apply(ops...)`
  (atomic patch-style operations) or hand edits → `Commit` = `Format` (one
  canonical aligned layout, idempotent) + `Verify` (reference parser
  confirms the formatted text holds exactly the same records and user
  comments as `WritePlain`) before anything replaces an original file.
  `Check` is the opt-in gate for files served on their own.
- `NewRecord`, `NewDirective` and `NewComment` are security boundaries:
  their arguments come from network clients and must never produce a
  second entry. They build entries from parts; they do not render text and
  parse it back. Operations carry records as `RR` data and go through
  `NewRecord`.
- Non-goals: serving DNS, DNSSEC, `$INCLUDE`/`$GENERATE` expansion, per-type
  RDATA validation, preserving original whitespace.

## Stack & conventions
- Go 1.27+ (`go 1.27` in `go.mod`, which is also the language version), no
  CGO, `go vet` and `golangci-lint` (default linters) clean, every exported
  identifier documented.
- Every source file starts with the Apache-2.0 SPDX header
  (`// SPDX-License-Identifier: Apache-2.0`).
- Layout: `doc.go`, `lex.go`, `parse.go`, `ast.go` (Entry), `zone.go`
  (Zone, Commit), `edit.go` (operations, queries), `names.go`, `ttl.go`,
  `escape.go`, `origin.go`, `record.go` (entry constructors), `equal.go`,
  `format.go`, `plain.go`, `serial.go`, `verify.go`, `idna.go`,
  `reverse.go`, `*_test.go`, `testdata/`.
- Errors: `*ParseError{Line, Col, Msg}` printed as `line L: msg`; record
  construction errors wrap `ErrInvalidRecord`; verification errors wrap
  `ErrUnsafeWrite`.
- Tests: unit tests for every spec section 8 and edit spec section 6
  example (byte-exact); property tests (idempotent `Format`, `Reformat` ≡
  `Parse().Format()`, `Verify` passes, `NewRecord` round-trips, operations
  round-trip); `FuzzParse` and `FuzzEdit` targets; golden files under
  `testdata/` with a `-update` flag; package coverage ≥ 90 %.

## Modern Go: this is a fresh start
The old implementation predates generics and iterators; do not carry its
shape forward. Reach for the current language and standard library whenever
it makes the code smaller, safer or faster, for example:
- range-over-func iterators (`iter.Seq`, `iter.Seq2`) for walking entries,
  records, comments and lexer tokens instead of building intermediate slices;
  offer them in addition to any slice-returning API the spec names, never
  instead of it;
- `slices`, `maps`, `cmp` and the `min`/`max`/`clear` builtins instead of
  hand-written loops; `slices.Clone` wherever an entry copy must not alias;
- `bytes.Lines`, `bytes.Cut`, `strings.SplitSeq`/`FieldsSeq` and friends for
  line and token handling, with careful attention to the spec's byte rules
  (CRLF, lone CR, NUL, BOM, opaque 0x80..0xFF);
- `strconv` and `unicode`-free ASCII-only folding helpers for names (RFC
  4343), never `strings.ToLower` on raw bytes;
- generics for small typed helpers (e.g. an aligned-column writer) where they
  remove duplication, not as decoration;
- in tests: `t.Context()`, `testing.B.Loop`, `t.Chdir`/`t.TempDir`,
  `testing/synctest` where time is involved (serial bumping), table tests
  with `t.Run`, testify assertions, raw string literals for multi-line zone
  text, and `go test -fuzz` for `FuzzParse` and `FuzzEdit`.
Stay inside the standard library for all of this; the dependency rule above
still holds. When a new stdlib API supersedes an older one, use the new one.

## Commands
- Build: `go build ./...`
- Verify: `gofmt -l .`, `go vet ./...`, `golangci-lint run`, `go test ./...`
- Coverage: `go test -coverprofile=coverage.out . && go tool cover -func=coverage.out`
- Benchmarks: `go test -run '^$' -bench . -benchmem .` (compare with benchstat before merging a change to the lexer, formatter or operations)
- Fuzz: `go test -run '^$' -fuzz=FuzzParse -fuzztime=30s .`
- Regenerate goldens: `go test ./... -update` (review the diff before committing)

## Critical rules
- User directives are absolute: if the user says `DO NOT <action>`, do not
  perform that action without explicit permission.
- Preserve user data and configuration; ask before changing if in doubt. Do
  not undo user choices in favor of your own approach without discussing first.
- Prefer minimal, targeted patches. Keep links absolute unless requested
  otherwise.
- Every text file must end with a final newline (`\n`).

## CI & releases
- `.github/workflows/ci.yml`: gofmt, vet, build, `go mod tidy -diff`, race
  tests with a 90 % coverage gate, golangci-lint, a 60 s `FuzzParse` smoke
  run and govulncheck. Keep it green; do not lower the gate.
- Dependabot (`.github/dependabot.yml`) groups Go and Actions updates weekly.
- Releases are cut by release-please (`release-please-config.json`): it reads
  Conventional Commits on `main`, maintains `CHANGELOG.md` and a release PR,
  and tags `vX.Y.Z` when that PR merges. Pre-1.0 rules: `feat` bumps minor,
  `fix` bumps patch, `!`/`BREAKING CHANGE` bumps minor. Commit types
  therefore matter; squash-merge PRs with a conventional title.

## Commit messages
- Conventional Commits: `<type>(<scope>): <description>` (see
  https://www.conventionalcommits.org/en/v1.0.0/#summary). Types in use:
  `feat`, `fix`, `perf`, `refactor`, `docs`, `test`, `build`, `ci`, `chore`.
