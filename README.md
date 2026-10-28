# masterfile

[![CI](https://github.com/vooon/go-masterfile/actions/workflows/ci.yml/badge.svg)](https://github.com/vooon/go-masterfile/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/vooon/go-masterfile.svg)](https://pkg.go.dev/github.com/vooon/go-masterfile)

A Go library for parsing, editing and formatting DNS zone files (RFC 1035
"master files") without losing anything a human put there: comments in
every position, blank lines, directives and the written form of values.

It is built for programs that edit zone files other people also edit by
hand and that a name server (BIND, Knot, CoreDNS) then loads:

- **Parse** keeps every entry and comment and never panics on any input.
- **ResolveOwners** gives records stable identities (owner relative to the
  apex, type, values, effective TTL) so they can be found, compared,
  replaced and removed regardless of position or `$ORIGIN` lines.
- **NewRecord** builds records safely from parts that may come from network
  clients: a value can never add a second record, a directive or a comment.
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
- **Zone** is an editing session: `Open`, then `Replace`, `Delete`,
  `DeleteOwner`, `AddRemove` and `Collapse` edit RRsets in place with
  placement hints and carried comments; `Select`, `Owners`, `RRSets` and
  `Serial` query; `Commit` runs the format-and-verify path and tells you
  whether anything changed.

```go
z, err := masterfile.Open(data, "example.org.")
rec, _ := masterfile.NewRecord("www", 0, dns.TypeA, "192.0.2.1")
_, err = z.Replace(
	masterfile.Selector{Owner: "www", Types: []uint16{dns.TypeA}},
	[]masterfile.Entry{rec},
	masterfile.ReplaceOptions{Mode: masterfile.ReplaceAll},
)
out, changed, err := z.Commit(true) // nil, false when the zone already said so
```

```go
f, err := masterfile.Parse(data)
apex, _ := f.Origin("")
err = f.ResolveOwners(apex)

rec, err := masterfile.NewRecord("www", 0, dns.TypeA, "192.0.2.1")
f.Entries = append(f.Entries, rec)

var plain, out bytes.Buffer
err = masterfile.WritePlain(&plain, apex, f.Entries)
err = masterfile.Format(&out, apex, f.Entries, true) // bumps the SOA serial
err = masterfile.Verify(apex, plain.Bytes(), out.Bytes())
```

The only dependency is [github.com/miekg/dns](https://github.com/miekg/dns)
for the RR type tables and the reference parser. Go 1.27 or later.

See [`docs/spec.md`](docs/spec.md) for the full specification and
[`docs/DESIGN.md`](docs/DESIGN.md) for implementation decisions.

## License

Apache-2.0, see [LICENSE](LICENSE).
