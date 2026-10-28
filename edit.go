// SPDX-License-Identifier: Apache-2.0

package masterfile

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// Errors of the editing operations. Commit also returns errors wrapping
// [ErrUnsafeWrite]; Open returns *[ParseError] for syntax errors.
var (
	ErrNoSOA        = errors.New("no SOA record")
	ErrApexMismatch = errors.New("apex mismatch")
	ErrNotInZone    = errors.New("owner not in zone")
	ErrNotFound     = errors.New("record not found")
)

// Zone is an editing session over one zone file: the entries as loaded,
// a working copy that the operations change, and the apex. It performs no
// I/O; the caller reads the file, applies operations, calls [Zone.Commit]
// and writes the bytes it returns. A Zone is meant for one
// read-modify-write cycle and is not safe for concurrent use.
type Zone struct {
	apex     string
	original []Entry
	entries  []Entry
}

// Open parses data, finds the apex (the first SOA's owner, with apex as the
// origin hint), requires an SOA and resolves every owner relative to the
// apex. When apex is not empty it must name the same zone as the SOA, or
// [ErrApexMismatch] is returned: a file edited over time must keep its
// origin.
func Open(data []byte, apex string) (*Zone, error) {
	f, err := Parse(data)
	if err != nil {
		return nil, err
	}
	found, soa := f.Origin(apex)
	if soa == nil {
		return nil, ErrNoSOA
	}
	if found == "" {
		return nil, fmt.Errorf("%w: the SOA owner is relative and no origin is known; set $ORIGIN or pass the apex", ErrNoSOA)
	}
	if apex != "" && !NameEqual(Fqdn(apex), found) {
		return nil, fmt.Errorf("%w: file has %s, caller expects %s", ErrApexMismatch, found, Fqdn(apex))
	}
	if err := f.ResolveOwners(found); err != nil {
		return nil, err
	}
	return &Zone{apex: found, original: slices.Clone(f.Entries), entries: f.Entries}, nil
}

// Apex returns the absolute apex of the zone.
func (z *Zone) Apex() string { return z.apex }

// Entries returns a copy of the working entries.
func (z *Zone) Entries() []Entry { return slices.Clone(z.entries) }

// AbsoluteOwner returns an entry's absolute owner, or "" for an entry that
// has none.
func (z *Zone) AbsoluteOwner(e Entry) string {
	if e.owner == "" {
		return ""
	}
	return Absolute(e.owner, z.apex)
}

// Changed reports whether the working entries differ in meaning from the
// entries as loaded (see [EntriesEqual]).
func (z *Zone) Changed() bool { return !EntriesEqual(z.original, z.entries) }

// Commit renders the working entries for writing. When nothing changed it
// returns nil, false, nil and the caller writes nothing. Otherwise it
// writes the plain and the formatted form (bumping the SOA serial when
// asked), verifies the pair with [Verify], and returns the formatted bytes.
// A verification failure is returned as is (it wraps [ErrUnsafeWrite]) and
// the caller must not write.
func (z *Zone) Commit(bumpSerial bool) (data []byte, changed bool, err error) {
	if !z.Changed() {
		return nil, false, nil
	}
	var plain, formatted bytes.Buffer
	if err := WritePlain(&plain, z.apex, z.entries); err != nil {
		return nil, false, err
	}
	if err := Format(&formatted, z.apex, z.entries, bumpSerial); err != nil {
		return nil, false, err
	}
	if err := Verify(z.apex, plain.Bytes(), formatted.Bytes()); err != nil {
		return nil, false, err
	}
	return formatted.Bytes(), true, nil
}

// Result reports what an operation did.
type Result struct {
	Matched  int // entries the selector matched
	Removed  int // entries dropped
	Inserted int // entries added
	Index    int // position of the first inserted entry, -1 if none
}

// Selector picks Record entries. Owner is absolute or apex-relative (see
// [Zone.Replace] for the rules); "" matches any owner and is accepted by
// the queries only. A nil Types or Contents matches any type or content;
// contents are compared in the [Entry.Content] form, with client strings
// normalised the same way (TXT and SPF as given, other types with
// whitespace runs collapsed to one space).
type Selector struct {
	Owner    string
	Types    []uint16
	Contents []string
}

// Anchor names records after which new records are placed: those with
// Owner, or those whose apex-relative owner starts with Prefix
// (ASCII case-insensitive). An anchor with neither matches nothing.
type Anchor struct {
	Owner  string
	Prefix string
}

// Placement lists anchors to try in order when an operation inserts records
// and found nothing to replace. The first anchor matching any Record entry
// decides: the new records go right after its last match. With no match,
// or an empty Placement, they are appended to the end.
type Placement []Anchor

// ReplaceMode selects what happens to matches after the first.
type ReplaceMode int

// Replace modes.
const (
	ReplaceAll   ReplaceMode = iota // every match goes; records take the first match's place
	ReplaceFirst                    // only the first match goes; later matches stay
)

// ReplaceOptions tunes [Zone.Replace].
type ReplaceOptions struct {
	Mode      ReplaceMode
	MustExist bool      // no match: ErrNotFound instead of inserting
	Placement Placement // where to insert when nothing matched
}

// owner normalises a client-supplied owner to the apex-relative form used
// by resolved entries. Owners may be absolute or apex-relative; one outside
// the zone is ErrNotInZone. An empty owner is returned as is.
func (z *Zone) owner(owner string) (string, error) {
	owner = strings.TrimSpace(owner)
	if owner == "" {
		return "", nil
	}
	abs := Absolute(owner, z.apex)
	if !InZone(abs, z.apex) {
		return "", fmt.Errorf("%w: %s is outside %s", ErrNotInZone, abs, z.apex)
	}
	return Relative(abs, z.apex), nil
}

// editOwner is owner for the editing operations, which need a real owner.
func (z *Zone) editOwner(owner string) (string, error) {
	o, err := z.owner(owner)
	if err == nil && o == "" {
		return "", fmt.Errorf("%w: empty owner", ErrNotInZone)
	}
	return o, err
}

// normalizeContent brings a client string into the [Entry.Content] form of
// a record of the given type: TXT and SPF are taken as is; anything else is
// tokenised like rdata and its decoded fields joined by one space, so
// quoting and spacing do not matter ("0 issue \"ca.example\"" matches a
// CAA record). A string that does not tokenise cleanly only gets its
// whitespace runs collapsed.
func normalizeContent(rtype uint16, s string) string {
	if n, ok := typeByNumber[rtype]; ok && (n == "TXT" || n == "SPF") {
		return s
	}
	if toks, err := tokenise(s); err == nil {
		vals := make([]string, 0, len(toks))
		for _, t := range toks {
			if t.kind != tokItem && t.kind != tokQuoted {
				vals = nil
				break
			}
			vals = append(vals, t.val)
		}
		if vals != nil {
			return strings.Join(vals, " ")
		}
	}
	return strings.Join(strings.Fields(s), " ")
}

// matches reports whether e is a Record matched by sel with its owner
// already normalised to owner.
func matches(sel Selector, owner string, e Entry) bool {
	if e.kind != Record {
		return false
	}
	if owner != "" && !NameEqual(e.owner, owner) {
		return false
	}
	if sel.Types != nil && !slices.Contains(sel.Types, e.rtype) {
		return false
	}
	if sel.Contents != nil {
		content := e.Content()
		return slices.ContainsFunc(sel.Contents, func(c string) bool { return normalizeContent(e.rtype, c) == content })
	}
	return true
}

// inSet reports whether e is a Record of the (owner, type) set.
func inSet(owner string, rtype uint16, e Entry) bool {
	return e.kind == Record && e.rtype == rtype && NameEqual(e.owner, owner)
}

// withOwner returns copies of records whose owner is set to owner where it
// differs.
func withOwner(records []Entry, owner string) []Entry {
	out := make([]Entry, len(records))
	for i, r := range records {
		if !NameEqual(r.owner, owner) {
			r = r.WithOwner(owner)
		}
		out[i] = r
	}
	return out
}

// placementIndex resolves a Placement against entries to an insertion
// index; anchors' owners must already be normalised.
func placementIndex(entries []Entry, p Placement) int {
	for _, a := range p {
		last := -1
		for i, e := range entries {
			if e.kind != Record || e.owner == "" {
				continue
			}
			if a.Owner != "" && NameEqual(e.owner, a.Owner) ||
				a.Prefix != "" && len(e.owner) >= len(a.Prefix) && NameEqual(e.owner[:len(a.Prefix)], a.Prefix) {
				last = i
			}
		}
		if last >= 0 {
			return last + 1
		}
	}
	return len(entries)
}

// placement normalises the anchors' owners.
func (z *Zone) placement(p Placement) (Placement, error) {
	out := make(Placement, len(p))
	for i, a := range p {
		o, err := z.owner(a.Owner)
		if err != nil {
			return nil, err
		}
		out[i] = Anchor{Owner: o, Prefix: a.Prefix}
	}
	return out, nil
}

// Replace replaces the records matching sel with records. The first match
// is replaced in place by all of records (zero or more); every later match
// is dropped (ReplaceAll) or kept (ReplaceFirst). Comments of dropped
// matches are carried onto the first inserted record. Without a match,
// MustExist returns [ErrNotFound] and changes nothing; otherwise records are
// inserted per Placement. Empty records and no match is a no-op.
//
// Owners in sel, records and anchors are absolute or apex-relative as a
// client would send them ("www", "www.example.org.", "@"); an owner outside
// the zone is [ErrNotInZone], and so is an empty selector owner. records
// are entries built with [NewRecord]; their owner is set to the selector's
// where it differs.
func (z *Zone) Replace(sel Selector, records []Entry, opt ReplaceOptions) (Result, error) {
	owner, err := z.editOwner(sel.Owner)
	if err != nil {
		return Result{}, err
	}
	p, err := z.placement(opt.Placement)
	if err != nil {
		return Result{}, err
	}
	records = withOwner(records, owner)
	res := Result{Index: -1}
	out := make([]Entry, 0, len(z.entries)+len(records))
	var carried []string
	for _, e := range z.entries {
		if !matches(sel, owner, e) {
			out = append(out, e)
			continue
		}
		res.Matched++
		switch {
		case res.Matched == 1:
			res.Removed++
			carried = append(carried, e.Comments()...)
			if len(records) > 0 {
				res.Index, res.Inserted = len(out), len(records)
				out = append(out, records...)
			}
		case opt.Mode == ReplaceAll:
			res.Removed++
			carried = append(carried, e.Comments()...)
		default:
			out = append(out, e)
		}
	}
	switch {
	case res.Matched > 0:
		if res.Inserted > 0 {
			out[res.Index] = out[res.Index].WithComments(carried...)
		}
	case opt.MustExist:
		return Result{Index: -1}, ErrNotFound
	case len(records) > 0:
		res.Index, res.Inserted = placementIndex(out, p), len(records)
		out = slices.Insert(out, res.Index, records...)
	}
	z.entries = out
	return res, nil
}

// Delete drops every record matching sel; an absent record is a no-op. It
// is Replace with no records and ReplaceAll.
func (z *Zone) Delete(sel Selector) (Result, error) {
	return z.Replace(sel, nil, ReplaceOptions{Mode: ReplaceAll})
}

// DeleteOwner drops every record with that owner, of any type, together
// with their comments.
func (z *Zone) DeleteOwner(owner string) (Result, error) {
	o, err := z.editOwner(owner)
	if err != nil {
		return Result{}, err
	}
	res := Result{Index: -1}
	out := slices.DeleteFunc(slices.Clone(z.entries), func(e Entry) bool {
		if e.kind == Record && NameEqual(e.owner, o) {
			res.Matched++
			res.Removed++
			return true
		}
		return false
	})
	z.entries = out
	return res, nil
}

// AddRemove edits one RRset (owner and type) in place, as DNS UPDATE does:
// entries whose content is in remove are dropped; then each entry of add
// whose content is still absent (and not a duplicate of an earlier add) is
// inserted right after the last remaining entry of the set, or per
// Placement when the set is empty. Adding a present value and removing an
// absent one are no-ops.
func (z *Zone) AddRemove(owner string, rtype uint16, add []Entry, remove []string, p Placement) (Result, error) {
	o, err := z.editOwner(owner)
	if err != nil {
		return Result{}, err
	}
	p, err = z.placement(p)
	if err != nil {
		return Result{}, err
	}
	removeSet := make(map[string]bool, len(remove))
	for _, r := range remove {
		removeSet[normalizeContent(rtype, r)] = true
	}
	res := Result{Index: -1}
	out := make([]Entry, 0, len(z.entries)+len(add))
	present := map[string]bool{}
	last := -1
	for _, e := range z.entries {
		if !inSet(o, rtype, e) {
			out = append(out, e)
			continue
		}
		res.Matched++
		c := e.Content()
		if removeSet[c] {
			res.Removed++
			continue
		}
		present[c] = true
		out = append(out, e)
		last = len(out) - 1
	}
	var toAdd []Entry
	for _, e := range withOwner(add, o) {
		if c := e.Content(); !present[c] {
			present[c] = true
			toAdd = append(toAdd, e)
		}
	}
	if len(toAdd) > 0 {
		res.Index, res.Inserted = placementIndex(out, p), len(toAdd)
		if last >= 0 {
			res.Index = last + 1
		}
		out = slices.Insert(out, res.Index, toAdd...)
	}
	z.entries = out
	return res, nil
}

// Collapse leaves the RRset (owner and type) with exactly one record of
// keep's content and none of the contents in drop; other contents are
// untouched. Entries with a content in drop are removed; of the entries
// equal to keep the first stays and later ones are removed; if none stayed,
// keep is inserted where the first dropped entry was, else per Placement.
// Comments of every removed entry are carried onto the record that stayed
// or was inserted.
func (z *Zone) Collapse(owner string, rtype uint16, drop []string, keep Entry, p Placement) (Result, error) {
	o, err := z.editOwner(owner)
	if err != nil {
		return Result{}, err
	}
	p, err = z.placement(p)
	if err != nil {
		return Result{}, err
	}
	keep = withOwner([]Entry{keep}, o)[0]
	keepContent := keep.Content()
	dropSet := make(map[string]bool, len(drop))
	for _, d := range drop {
		dropSet[normalizeContent(rtype, d)] = true
	}
	res := Result{Index: -1}
	out := make([]Entry, 0, len(z.entries)+1)
	var carried []string
	keepAt, firstDropped := -1, -1
	for _, e := range z.entries {
		if !inSet(o, rtype, e) {
			out = append(out, e)
			continue
		}
		res.Matched++
		switch c := e.Content(); {
		case dropSet[c]:
			if firstDropped < 0 {
				firstDropped = len(out)
			}
			res.Removed++
			carried = append(carried, e.Comments()...)
		case c == keepContent && keepAt >= 0:
			res.Removed++
			carried = append(carried, e.Comments()...)
		case c == keepContent:
			keepAt = len(out)
			out = append(out, e)
		default:
			out = append(out, e)
		}
	}
	if keepAt < 0 {
		keepAt = firstDropped
		if keepAt < 0 {
			keepAt = placementIndex(out, p)
		}
		res.Index, res.Inserted = keepAt, 1
		out = slices.Insert(out, keepAt, keep)
	}
	out[keepAt] = out[keepAt].WithComments(carried...)
	z.entries = out
	return res, nil
}

// Select returns copies of the records matching sel in file order. An
// owner outside the zone matches nothing; an empty owner matches any.
func (z *Zone) Select(sel Selector) []Entry {
	owner, err := z.owner(sel.Owner)
	if err != nil {
		return nil
	}
	var out []Entry
	for _, e := range z.entries {
		if matches(sel, owner, e) {
			out = append(out, e)
		}
	}
	return out
}

// Owners returns the absolute owners of the records matching sel,
// deduplicated (ASCII case-insensitively, first spelling wins), in file
// order.
func (z *Zone) Owners(sel Selector) []string {
	var out []string
	for _, e := range z.Select(sel) {
		abs := z.AbsoluteOwner(e)
		if abs != "" && !slices.ContainsFunc(out, func(s string) bool { return NameEqual(s, abs) }) {
			out = append(out, abs)
		}
	}
	return out
}

// RRSet is one group of records with the same owner and type.
type RRSet struct {
	Owner    string   // absolute
	Type     string   // upper-case
	TTL      uint32   // effective TTL of the first record, 0 when unknown
	Contents []string // in file order
}

// RRSets groups the records by owner and type in order of first
// appearance, with the $TTL in force applied to records without an
// explicit TTL. Records without an owner are skipped.
func (z *Zone) RRSets() []RRSet {
	var (
		sets  []RRSet
		index = map[string]int{}
		ttl   ttlState
	)
	for _, e := range z.entries {
		ttl.apply(e)
		if e.kind != Record || e.owner == "" {
			continue
		}
		owner := z.AbsoluteOwner(e)
		key := strings.ToLower(owner) + "\x00" + e.typ
		i, ok := index[key]
		if !ok {
			secs, _ := ttl.effective(e)
			i = len(sets)
			index[key] = i
			sets = append(sets, RRSet{Owner: owner, Type: e.typ, TTL: secs})
		}
		sets[i].Contents = append(sets[i].Contents, e.Content())
	}
	return sets
}

// Serial returns the serial of the first SOA record, or false when it is
// absent or not a 32-bit number.
func (z *Zone) Serial() (uint32, bool) {
	for _, e := range z.entries {
		if e.kind == Record && e.typ == "SOA" {
			if len(e.fields) < 3 {
				return 0, false
			}
			n, err := strconv.ParseUint(e.fields[2].Value, 10, 32)
			return uint32(n), err == nil
		}
	}
	return 0, false
}
