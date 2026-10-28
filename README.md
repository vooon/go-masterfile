# masterfile

[![CI](https://github.com/vooon/go-masterfile/actions/workflows/ci.yml/badge.svg)](https://github.com/vooon/go-masterfile/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/vooon/go-masterfile.svg)](https://pkg.go.dev/github.com/vooon/go-masterfile)

A Go library for parsing, editing and formatting DNS zone files (RFC 1035
"master files") without losing anything a human put there: comments in
every position, blank lines, directives and the written form of values.

It is built for programs that edit zone files other people also edit by
hand and that a name server (BIND, Knot, CoreDNS) then loads:

- **Parse** keeps every entry and comment, never panics on any input, and
  gives every record a stable identity (owner relative to the apex, type,
  values, effective TTL) so records can be found, compared, replaced and
  removed regardless of position or `$ORIGIN` lines. **New** starts a zone
  from nothing.
- **NewRecord**, **NewDirective** and **NewComment** build entries safely
  from parts that may come from network clients: a value can never add a
  second record, a directive or a comment.
- **Format** writes one canonical, aligned layout that is idempotent.
- **Verify** proves with an independent parser (miekg/dns) that the
  formatted text holds exactly the intended records and comments before it
  replaces the original.
- **ToASCII** and **ToUnicode** convert internationalised names between
  their Unicode and `xn--` forms, label by label, at your input and display
  boundaries.
- **InZone**, **LongestZone**, **ReverseName**, **ReverseAddr**,
  **IsReverseZone** and **ReversePrefix** route names to zones and build or
  parse `in-addr.arpa` and `ip6.arpa` names and prefixes.
- **Apply** runs patch-style operations atomically: `Replace`, `Insert`,
  `Delete`, `DeleteOwner`, `AddRemove` and `Collapse` edit RRsets in place,
  put new records where a human would (next to the owner's block, the
  `_acme-challenge.*` group, the siblings, the same type for hosts) and carry the
  comments of what they replace. `Select`, `Owners`, `RRSets`, `Serial`
  and `SOA` query; `Check` says whether a file is serveable on its own.
- **Commit** renders only when something changed, through the
  format-and-verify path.

```go
z, err := masterfile.Parse(data, "example.org.") // apex checked, owners resolved
results, err := z.Apply(
	masterfile.Replace{
		Selector: masterfile.Selector{Owner: "www", Types: []uint16{dns.TypeA}},
		Records:  []masterfile.RR{{Type: dns.TypeA, Content: "192.0.2.1"}},
	},
	masterfile.Insert{Owner: "_acme-challenge", Records: []masterfile.RR{{Type: dns.TypeTXT, Content: token}}},
)
out, changed, err := z.Commit(true) // nil, false when the zone already said so
```

Hand edits work too: range over `z.Records()`, splice `z.Entries`, set
`z.Changed = true`, then `Commit`. A file can be built from nothing with
`New(apex)` and the entry constructors.

The only dependency is [github.com/miekg/dns](https://github.com/miekg/dns)
for the RR type tables and the reference parser. Go 1.27 or later.

See [`docs/spec.md`](docs/spec.md) for the full specification and
[`docs/DESIGN.md`](docs/DESIGN.md) for implementation decisions.

## License

Apache-2.0, see [LICENSE](LICENSE).
