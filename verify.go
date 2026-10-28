// SPDX-License-Identifier: Apache-2.0

package masterfile

import (
	"bytes"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/miekg/dns"
)

// ErrUnsafeWrite is wrapped by every error of [Verify].
var ErrUnsafeWrite = errors.New("unsafe write")

// Records parses data with the reference parser (miekg/dns, origin apex,
// $INCLUDE disallowed) and returns the multiset of its records as
// rr.String() lower-cased with the SOA serial zeroed, mapped to their
// counts. It is exported for tests.
func Records(apex string, data []byte) (map[string]int, error) {
	if apex == "" {
		apex = "."
	}
	zp := dns.NewZoneParser(bytes.NewReader(data), Fqdn(apex), "")
	zp.SetIncludeAllowed(false)
	out := map[string]int{}
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		if soa, isSOA := rr.(*dns.SOA); isSOA {
			soa = dns.Copy(soa).(*dns.SOA) //nolint:errcheck // Copy preserves the type
			soa.Serial = 0
			rr = soa
		}
		out[strings.ToLower(rr.String())]++
	}
	if err := zp.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// Comments parses data with this package's parser and returns every comment
// in file order. It is exported for tests.
func Comments(data []byte) ([]string, error) {
	z, err := Parse(data, "")
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range z.Entries {
		out = append(out, e.Comments()...)
	}
	return out, nil
}

// Verify proves that formatted is a safe replacement for plain (both
// renderings of the same zone, see [Zone.WritePlain] and [Zone.Format]):
// both must
// parse with the reference parser, hold the same multiset of records (SOA
// serial ignored), and every user comment of plain (see [UserComment]) must
// occur in a comment of formatted. Errors wrap [ErrUnsafeWrite] and list
// lost ("-") and added ("+") records.
func Verify(apex string, plain, formatted []byte) error {
	rp, err := Records(apex, plain)
	if err != nil {
		return fmt.Errorf("%w: plain text does not parse: %w", ErrUnsafeWrite, err)
	}
	rf, err := Records(apex, formatted)
	if err != nil {
		return fmt.Errorf("%w: formatted text does not parse: %w", ErrUnsafeWrite, err)
	}
	var diff []string
	for _, k := range slices.Sorted(maps.Keys(rp)) {
		for range rp[k] - rf[k] {
			diff = append(diff, "-"+k)
		}
	}
	for _, k := range slices.Sorted(maps.Keys(rf)) {
		for range rf[k] - rp[k] {
			diff = append(diff, "+"+k)
		}
	}
	if len(diff) > 0 {
		return fmt.Errorf("%w: records differ:\n%s", ErrUnsafeWrite, strings.Join(diff, "\n"))
	}
	cp, err := Comments(plain)
	if err != nil {
		return fmt.Errorf("%w: plain text: %w", ErrUnsafeWrite, err)
	}
	cf, err := Comments(formatted)
	if err != nil {
		return fmt.Errorf("%w: formatted text: %w", ErrUnsafeWrite, err)
	}
	for _, c := range cp {
		u := UserComment(c)
		if u == "" {
			continue
		}
		if !slices.ContainsFunc(cf, func(x string) bool { return strings.Contains(x, u) }) {
			return fmt.Errorf("%w: comment lost: %s", ErrUnsafeWrite, u)
		}
	}
	return nil
}
