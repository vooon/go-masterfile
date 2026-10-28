// SPDX-License-Identifier: Apache-2.0

package masterfile

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

// Errors of [Parse] and [Zone.Apply]. [Zone.Commit] returns errors
// wrapping [ErrUnsafeWrite]; Parse returns *[ParseError] for syntax errors.
var (
	ErrApexMismatch = errors.New("apex mismatch")
	ErrNotInZone    = errors.New("owner not in zone")
	ErrNotFound     = errors.New("record not found")
)

// Op is one editing operation, applied with [Zone.Apply]. The operations
// are [Replace], [Insert], [Delete], [DeleteOwner], [AddRemove] and
// [Collapse]: plain values that can be built up, logged and applied
// together.
type Op interface {
	apply(z *Zone) (Result, error)
}

// RR is a record as an operation carries it: data, not an [Entry]. Apply
// builds the entry with [NewRecord], so the security boundary holds for
// values that come from network clients.
type RR struct {
	Type    uint16
	TTL     uint32 // 0: no explicit TTL
	Content string // PowerDNS content form: rdata fields, TXT text as is
}

// entry builds the record for owner (already normalised).
func (r RR) entry(owner string) (Entry, error) { return NewRecord(owner, r.TTL, r.Type, r.Content) }

// reown returns records with their owner respelled as owner (the spelling
// the zone already uses) where it differs.
func reown(records []Entry, owner string) []Entry {
	out := slices.Clone(records)
	for i, r := range out {
		if r.owner != owner {
			out[i] = r.WithOwner(owner)
		}
	}
	return out
}

func entries(owner string, rrs []RR) ([]Entry, error) {
	out := make([]Entry, len(rrs))
	for i, r := range rrs {
		e, err := r.entry(owner)
		if err != nil {
			return nil, err
		}
		out[i] = e
	}
	return out, nil
}

// Result reports what an operation did.
type Result struct {
	Matched  int  // entries the selector matched
	Removed  int  // entries dropped
	Inserted int  // entries added
	Index    int  // position of the first inserted entry, -1 if none
	Changed  bool // the zone's meaning changed (also recorded in Zone.Changed)
}

// Selector picks Record entries. Owner is absolute or apex-relative (see
// [Replace] for the rules); "" matches any owner and is accepted by the
// queries only. A nil Types or Contents matches any type or content;
// contents are compared in the [Entry.Content] form, with client strings
// normalised the same way (TXT and SPF as given; other types tokenised
// like rdata and their decoded fields joined by one space).
type Selector struct {
	Owner    string
	Types    []uint16
	Contents []string
}

// Anchor names records after which new records are placed: those with
// Owner; those whose apex-relative owner starts with Prefix (ASCII
// case-insensitive); those whose owner is Under or below it; those of type
// Type. Conditions that are set must all hold; an anchor with none set
// matches nothing. Owner and Under are client-form names like a selector's.
type Anchor struct {
	Owner  string
	Prefix string
	Under  string
	Type   uint16
}

// Placement lists anchors to try in order when an operation inserts records
// and found nothing to replace. The first anchor matching any Record entry
// decides: the new records go right after its last match, and after the
// records that follow it with the same owner, so an owner's block is never
// split. With no match, or an empty Placement, they are appended to the
// end. [Zone.DefaultPlacement] builds the list a human would use.
type Placement []Anchor

// Apply runs the operations in order and reports what each did. It is
// atomic: when one fails, the error names it and the zone is left exactly
// as it was, with nothing applied. Errors are [ErrNotInZone],
// [ErrNotFound] and, for records that cannot be built, [ErrInvalidRecord].
func (z *Zone) Apply(ops ...Op) ([]Result, error) {
	work := *z // shallow: every operation builds a new entry slice
	results := make([]Result, 0, len(ops))
	for i, op := range ops {
		r, err := op.apply(&work)
		if err != nil {
			return nil, fmt.Errorf("op %d (%T): %w", i, op, err)
		}
		results = append(results, r)
	}
	z.Entries, z.Changed = work.Entries, work.Changed
	return results, nil
}

// ReplaceMode selects what happens to matches after the first.
type ReplaceMode int

// Replace modes.
const (
	ReplaceAll   ReplaceMode = iota // every match goes; records take the first match's place
	ReplaceFirst                    // only the first match goes; later matches stay
)

// owner normalises a client-supplied owner to the apex-relative form.
// Owners may be absolute or apex-relative; one outside the zone is
// ErrNotInZone. An empty owner is returned as is.
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

// matcher returns the predicate "e is a Record matched by sel", with sel's
// owner already normalised to owner. The client contents are normalised
// once per record type met, not once per entry.
func (z *Zone) matcher(sel Selector, owner string) func(e Entry) bool {
	var norm map[uint16][]string
	return func(e Entry) bool {
		if e.kind != Record {
			return false
		}
		if owner != "" && !NameEqual(z.relOwner(e), owner) {
			return false
		}
		if sel.Types != nil && !slices.Contains(sel.Types, e.rtype) {
			return false
		}
		if sel.Contents == nil {
			return true
		}
		cs, ok := norm[e.rtype]
		if !ok {
			cs = make([]string, len(sel.Contents))
			for i, c := range sel.Contents {
				cs[i] = normalizeContent(e.rtype, c)
			}
			if norm == nil {
				norm = make(map[uint16][]string, 1)
			}
			norm[e.rtype] = cs
		}
		return slices.Contains(cs, e.Content())
	}
}

// inSet reports whether e is a Record of the (owner, type) set.
func (z *Zone) inSet(owner string, rtype uint16, e Entry) bool {
	return e.kind == Record && e.rtype == rtype && NameEqual(z.relOwner(e), owner)
}

// placementIndex resolves a Placement against entries to an insertion
// index; the anchors' owners must already be normalised.
func (z *Zone) placementIndex(entries []Entry, p Placement) int {
	for _, a := range p {
		if a.Owner == "" && a.Prefix == "" && a.Under == "" && a.Type == 0 {
			continue
		}
		last := -1
		for i, e := range entries {
			if e.kind != Record || e.owner == "" {
				continue
			}
			rel := z.relOwner(e)
			if a.Owner != "" && !NameEqual(rel, a.Owner) {
				continue
			}
			if a.Prefix != "" && (len(rel) < len(a.Prefix) || !NameEqual(rel[:len(a.Prefix)], a.Prefix)) {
				continue
			}
			if a.Under != "" && !underRel(rel, a.Under) {
				continue
			}
			if a.Type != 0 && e.rtype != a.Type {
				continue
			}
			last = i
		}
		if last < 0 {
			continue
		}
		// Do not split the matched owner's block: skip the records that
		// follow with the same owner (an A/AAAA pair after a Type anchor).
		for last+1 < len(entries) && entries[last+1].kind == Record &&
			NameEqual(z.relOwner(entries[last+1]), z.relOwner(entries[last])) {
			last++
		}
		return last + 1
	}
	return len(entries)
}

// underRel reports whether the apex-relative owner rel is parent or below
// it; parent "@" covers every owner in the zone.
func underRel(rel, parent string) bool {
	if parent == "@" {
		return true
	}
	return NameEqual(rel, parent) || len(rel) > len(parent) &&
		NameEqual(rel[len(rel)-len(parent):], parent) && rel[len(rel)-len(parent)-1] == '.' &&
		!escapedAt(rel, len(rel)-len(parent)-1)
}

// placement normalises the anchors' owners.
func (z *Zone) placement(p Placement) (Placement, error) {
	out := make(Placement, len(p))
	for i, a := range p {
		o, err := z.owner(a.Owner)
		if err != nil {
			return nil, err
		}
		u, err := z.owner(a.Under)
		if err != nil {
			return nil, err
		}
		out[i] = Anchor{Owner: o, Prefix: a.Prefix, Under: u, Type: a.Type}
	}
	return out, nil
}

// DefaultPlacement is where a human would add records of owner and rtype:
// after the owner's own records; else after the records whose first label
// is the same (every _acme-challenge.* together); else after the records
// under the same parent name (siblings); else after the last record of
// the same type; else at the end. The owner is in client form; one outside
// the zone yields the type anchor alone.
func (z *Zone) DefaultPlacement(owner string, rtype uint16) Placement {
	rel, err := z.editOwner(owner)
	if err != nil {
		return Placement{{Type: rtype}}
	}
	p := Placement{{Owner: rel}}
	if rel != "@" {
		p = append(p, Anchor{Under: rel})
		for i := range len(rel) {
			if rel[i] == '.' && !escapedAt(rel, i) {
				p[1] = Anchor{Prefix: rel[:i+1]}
				p = append(p, Anchor{Under: rel[i+1:]})
				break
			}
		}
	}
	return append(p, Anchor{Type: rtype})
}

// Replace replaces the records matching Selector with Records. The first
// match is replaced in place by all of Records (zero or more); every later
// match is dropped (ReplaceAll) or kept (ReplaceFirst). Comments of dropped
// matches are carried onto the first inserted record. Without a match,
// MustExist fails with [ErrNotFound]; otherwise Records are inserted per
// Placement. Empty Records and no match is a no-op.
//
// Owners in the selector and the anchors are absolute or apex-relative as a
// client would send them ("www", "www.example.org.", "@"); an owner outside
// the zone is [ErrNotInZone], and so is an empty selector owner. Records
// get the selector's owner.
type Replace struct {
	Selector
	Records   []RR
	Mode      ReplaceMode
	MustExist bool
	Placement Placement
}

func (op Replace) apply(z *Zone) (Result, error) {
	owner, err := z.editOwner(op.Owner)
	if err != nil {
		return Result{}, err
	}
	p, err := z.placement(op.Placement)
	if err != nil {
		return Result{}, err
	}
	records, err := entries(owner, op.Records)
	if err != nil {
		return Result{}, err
	}
	res := Result{Index: -1}
	out := make([]Entry, 0, len(z.Entries)+len(records))
	var carried []string
	matches := z.matcher(op.Selector, owner)
	for _, e := range z.Entries {
		if !matches(e) {
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
				out = append(out, reown(records, z.relOwner(e))...)
			}
		case op.Mode == ReplaceAll:
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
	case op.MustExist:
		return Result{Index: -1}, ErrNotFound
	case len(records) > 0:
		res.Index, res.Inserted = z.placementIndex(out, p), len(records)
		out = slices.Insert(out, res.Index, records...)
	}
	res.Changed = z.set(out)
	return res, nil
}

// Insert adds Records under Owner, skipping those the zone already holds
// (same owner, type and content). They go per Placement, or per
// [Zone.DefaultPlacement] for the first record's type when Placement is
// empty. Nothing else is touched.
type Insert struct {
	Owner     string
	Records   []RR
	Placement Placement
}

func (op Insert) apply(z *Zone) (Result, error) {
	o, err := z.editOwner(op.Owner)
	if err != nil {
		return Result{}, err
	}
	records, err := entries(o, op.Records)
	if err != nil {
		return Result{}, err
	}
	res := Result{Index: -1}
	if len(records) == 0 {
		return res, nil
	}
	p := op.Placement
	if len(p) == 0 {
		p = z.DefaultPlacement(o, records[0].rtype)
	}
	if p, err = z.placement(p); err != nil {
		return Result{}, err
	}
	toAdd := slices.DeleteFunc(records, func(r Entry) bool {
		dup := slices.ContainsFunc(z.Entries, func(e Entry) bool { return z.inSet(o, r.rtype, e) && e.Content() == r.Content() })
		if dup {
			res.Matched++
		}
		return dup
	})
	out := slices.Clone(z.Entries)
	if len(toAdd) > 0 {
		res.Index, res.Inserted = z.placementIndex(out, p), len(toAdd)
		out = slices.Insert(out, res.Index, toAdd...)
	}
	res.Changed = z.set(out)
	return res, nil
}

// Delete drops every record matching Selector; an absent record is a
// no-op. It is [Replace] with no records and ReplaceAll.
type Delete struct {
	Selector
}

func (op Delete) apply(z *Zone) (Result, error) {
	return Replace{Selector: op.Selector, Mode: ReplaceAll}.apply(z)
}

// DeleteOwner drops every record with that owner, of any type, together
// with their comments.
type DeleteOwner struct {
	Owner string
}

func (op DeleteOwner) apply(z *Zone) (Result, error) {
	o, err := z.editOwner(op.Owner)
	if err != nil {
		return Result{}, err
	}
	res := Result{Index: -1}
	out := slices.DeleteFunc(slices.Clone(z.Entries), func(e Entry) bool {
		if e.kind == Record && NameEqual(z.relOwner(e), o) {
			res.Matched++
			res.Removed++
			return true
		}
		return false
	})
	res.Changed = z.set(out)
	return res, nil
}

// AddRemove edits one RRset (Owner and Type) in place, as DNS UPDATE does:
// entries whose content is in Remove are dropped; then each content of Add
// that is still absent (and not a duplicate of an earlier one) is inserted
// as a record with TTL right after the last remaining entry of the set, or
// per Placement when the set is empty. Adding a present value and removing
// an absent one are no-ops.
type AddRemove struct {
	Owner     string
	Type      uint16
	TTL       uint32 // for added records; 0: no explicit TTL
	Add       []string
	Remove    []string
	Placement Placement
}

func (op AddRemove) apply(z *Zone) (Result, error) {
	o, err := z.editOwner(op.Owner)
	if err != nil {
		return Result{}, err
	}
	p, err := z.placement(op.Placement)
	if err != nil {
		return Result{}, err
	}
	removeSet := make(map[string]bool, len(op.Remove))
	for _, r := range op.Remove {
		removeSet[normalizeContent(op.Type, r)] = true
	}
	res := Result{Index: -1}
	out := make([]Entry, 0, len(z.Entries)+len(op.Add))
	present := map[string]bool{}
	last := -1
	for _, e := range z.Entries {
		if !z.inSet(o, op.Type, e) {
			out = append(out, e)
			continue
		}
		res.Matched++
		o = z.relOwner(e) // keep the zone's spelling
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
	for _, a := range op.Add {
		e, err := RR{Type: op.Type, TTL: op.TTL, Content: a}.entry(o)
		if err != nil {
			return Result{}, err
		}
		if c := e.Content(); !present[c] {
			present[c] = true
			toAdd = append(toAdd, e)
		}
	}
	if len(toAdd) > 0 {
		res.Index, res.Inserted = z.placementIndex(out, p), len(toAdd)
		if last >= 0 {
			res.Index = last + 1
		}
		out = slices.Insert(out, res.Index, toAdd...)
	}
	res.Changed = z.set(out)
	return res, nil
}

// Collapse leaves the RRset (Owner and Type) with exactly one record of
// content Keep and none of the contents in Drop; other contents are
// untouched. Entries with a content in Drop are removed; of the entries
// equal to Keep the first stays and later ones are removed; if none stayed,
// Keep is inserted (with KeepTTL) where the first dropped entry was, else
// per Placement. Comments of every removed entry are carried onto the
// record that stayed or was inserted.
type Collapse struct {
	Owner     string
	Type      uint16
	Drop      []string
	Keep      string
	KeepTTL   uint32 // 0: no explicit TTL
	Placement Placement
}

func (op Collapse) apply(z *Zone) (Result, error) {
	o, err := z.editOwner(op.Owner)
	if err != nil {
		return Result{}, err
	}
	p, err := z.placement(op.Placement)
	if err != nil {
		return Result{}, err
	}
	keep, err := RR{Type: op.Type, TTL: op.KeepTTL, Content: op.Keep}.entry(o)
	if err != nil {
		return Result{}, err
	}
	keepContent := keep.Content()
	dropSet := make(map[string]bool, len(op.Drop))
	for _, d := range op.Drop {
		dropSet[normalizeContent(op.Type, d)] = true
	}
	res := Result{Index: -1}
	out := make([]Entry, 0, len(z.Entries)+1)
	var carried []string
	keepAt, firstDropped := -1, -1
	for _, e := range z.Entries {
		if !z.inSet(o, op.Type, e) {
			out = append(out, e)
			continue
		}
		res.Matched++
		keep = reown([]Entry{keep}, z.relOwner(e))[0]
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
			keepAt = z.placementIndex(out, p)
		}
		res.Index, res.Inserted = keepAt, 1
		out = slices.Insert(out, keepAt, keep)
	}
	out[keepAt] = out[keepAt].WithComments(carried...)
	res.Changed = z.set(out)
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
	matches := z.matcher(sel, owner)
	for _, e := range z.Entries {
		if matches(e) {
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
	for _, e := range z.Entries {
		ttl.apply(e)
		if e.kind != Record || e.owner == "" {
			continue
		}
		owner := z.AbsoluteOwner(e)
		key := foldASCII(owner) + "\x00" + e.typ
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
