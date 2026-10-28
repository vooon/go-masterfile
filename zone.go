// SPDX-License-Identifier: Apache-2.0

package masterfile

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"iter"
	"strconv"
)

// Zone is a zone file in memory: its entries in file order and its apex.
// [Parse] builds one from text and [New] builds an empty one. From there
// the caller ranges over or edits Entries directly, or applies the editing
// operations ([Zone.Replace] and friends), and finally renders the result
// with [Zone.Commit] (or [Zone.Format]) and writes the bytes itself: the
// package never touches files.
//
// Every record's owner is explicit and relative to the apex ("@" for the
// apex itself, "www" for www.<apex>, the absolute name for anything
// outside the zone), so an entry's meaning does not depend on its position
// or on $ORIGIN lines and entries can be moved, inserted and compared
// freely.
//
// Changed records whether the zone differs in meaning from what was parsed
// or created: the editing operations set it when they change something,
// and code that edits Entries directly sets it itself. [Zone.Commit] reads
// it and renders nothing while it is false. A Zone is not safe for
// concurrent use.
type Zone struct {
	Entries  []Entry
	Changed  bool
	apex     string
	origin   string // the origin in force before any $ORIGIN line (see Parse)
	noOrigin bool   // the apex is the root fallback, not a known origin
}

// New returns an empty zone with the given apex (made absolute; "" is the
// root). It holds no entries, not even a $ORIGIN line: append one built
// with [NewDirective] if the file should be self-describing.
func New(apex string) *Zone {
	return &Zone{apex: Fqdn(apex), origin: Fqdn(apex), noOrigin: apex == ""}
}

// Apex returns the absolute apex of the zone.
func (z *Zone) Apex() string { return z.apex }

// Errors of [Zone.Check].
var (
	ErrNoOrigin = errors.New("no origin")
	ErrNoSOA    = errors.New("no SOA record")
)

// Check reports whether the zone is complete enough for a name server to
// load on its own: its origin must be known (an apex given to [Parse] or
// [New], a $ORIGIN line, or an SOA whose owner resolves to a name), else
// [ErrNoOrigin], and it must hold an SOA record, else [ErrNoSOA]. Parse
// does not insist on either, so fragments meant for $INCLUDE parse and
// format like any other file; callers that serve a file call Check.
func (z *Zone) Check() error {
	if z.noOrigin {
		return fmt.Errorf("%w: no apex given, no $ORIGIN and no absolute SOA owner", ErrNoOrigin)
	}
	if _, ok := z.SOA(); !ok {
		return ErrNoSOA
	}
	return nil
}

// Records iterates over the Record entries with their index in Entries.
func (z *Zone) Records() iter.Seq2[int, Entry] {
	return func(yield func(int, Entry) bool) {
		for i, e := range z.Entries {
			if e.kind == Record && !yield(i, e) {
				return
			}
		}
	}
}

// SOA returns the first SOA record and true, or false when there is none.
func (z *Zone) SOA() (Entry, bool) {
	for _, e := range z.Records() {
		if e.typ == "SOA" {
			return e, true
		}
	}
	return Entry{}, false
}

// Serial returns the serial of the first SOA record, or false when there
// is no SOA or the serial is not a 32-bit number.
func (z *Zone) Serial() (uint32, bool) {
	soa, ok := z.SOA()
	if !ok || len(soa.fields) < 3 {
		return 0, false
	}
	n, err := strconv.ParseUint(soa.fields[2].Value, 10, 32)
	return uint32(n), err == nil
}

// AbsoluteOwner returns an entry's absolute owner, or "" for an entry that
// has none.
func (z *Zone) AbsoluteOwner(e Entry) string {
	if e.owner == "" {
		return ""
	}
	return Absolute(e.owner, z.apex)
}

// relOwner returns an entry's owner relative to the apex, normalising
// owners that were set by hand in absolute form.
func (z *Zone) relOwner(e Entry) string {
	if e.owner == "" {
		return ""
	}
	return Relative(Absolute(e.owner, z.apex), z.apex)
}

// Format writes the zone in the canonical layout: aligned owner, TTL,
// class, type and value columns; owners relative to the $ORIGIN in force
// and blank when repeated; TTLs equal to the $TTL in force dropped; SOA and
// multi-string TXT records multi-line; long DNSKEY, DS and RRSIG data split
// into 55-byte pieces; comments kept in place. With bumpSerial the first
// SOA's serial is replaced by [Increase] of itself. The output is
// idempotent: formatting it again (without a bump) reproduces it byte for
// byte. Write errors are returned.
func (z *Zone) Format(w io.Writer, bumpSerial bool) error {
	return format(w, z.origin, z.apex, z.Entries, bumpSerial)
}

// WritePlain writes the zone without alignment: fields separated by one
// space, owners relative to the $ORIGIN in force, values as written,
// multi-line only when a comment position requires it, comments in place.
// It is deliberately simple and is the reference that [Verify] checks
// [Zone.Format] against. Its exact spacing is not part of the contract.
func (z *Zone) WritePlain(w io.Writer) error { return writePlain(w, z.origin, z.apex, z.Entries) }

// Commit renders the zone for writing. While Changed is false it returns
// nil, false, nil and the caller writes nothing. Otherwise it writes the
// plain and the formatted form (bumping the SOA serial when asked),
// verifies the pair with [Verify], and returns the formatted bytes. A
// verification failure is returned as is (it wraps [ErrUnsafeWrite]) and
// the caller must not write. Commit leaves Changed as it is: a Zone is one
// read-modify-write cycle.
func (z *Zone) Commit(bumpSerial bool) (data []byte, changed bool, err error) {
	if !z.Changed {
		return nil, false, nil
	}
	var plain, formatted bytes.Buffer
	if err := z.WritePlain(&plain); err != nil {
		return nil, false, err
	}
	if err := z.Format(&formatted, bumpSerial); err != nil {
		return nil, false, err
	}
	if err := Verify(z.apex, plain.Bytes(), formatted.Bytes()); err != nil {
		return nil, false, err
	}
	return formatted.Bytes(), true, nil
}

// set installs out as the entries, flags the zone as changed when the
// meaning differs (see [EntriesEqual]), and reports whether it did.
func (z *Zone) set(out []Entry) bool {
	changed := !EntriesEqual(z.Entries, out)
	z.Entries = out
	z.Changed = z.Changed || changed
	return changed
}
