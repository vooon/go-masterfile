// SPDX-License-Identifier: Apache-2.0

// Package masterfile parses, edits and writes DNS zone files (RFC 1035
// "master files") while keeping everything a human put there: comments in
// every position, blank lines, directives and the written form of values.
//
// The package is a plain library over byte slices. It never reads or writes
// files itself and has no scheduling or network code. Its one third-party
// dependency is github.com/miekg/dns, used for the RR type and class name
// tables and as the independent reference parser in [Verify].
//
// # Pipeline
//
// Everything revolves around one type, [Zone]:
//
//  1. [Parse] the text into a Zone (or start one with [New]). Parse finds
//     the apex, checks it against the caller's expectation and makes every
//     record owner explicit and relative to the apex, so entries can be
//     found, moved, compared and replaced without regard to their position
//     or to $ORIGIN lines.
//  2. Edit it: range over [Zone.Records] and splice [Zone.Entries] by hand
//     (setting [Zone.Changed]), or apply the operations [Zone.Replace],
//     [Zone.Delete], [Zone.DeleteOwner], [Zone.AddRemove] and
//     [Zone.Collapse], which place records where a human would and set
//     Changed only when the zone's meaning changed. [NewRecord],
//     [NewDirective] and [NewComment] build entries safely from parts that
//     may come from network clients.
//  3. [Zone.Commit] renders the result: nothing while Changed is false,
//     otherwise the canonical layout of [Zone.Format], proven safe by
//     [Verify] against the plain rendering of [Zone.WritePlain]. The caller
//     writes the bytes.
//
// [Reformat] is Parse and Format in one call for formatter commands.
package masterfile
