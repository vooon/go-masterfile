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
// A typical edit goes through these steps:
//
//  1. [Parse] the text into a [File] of entries (blank lines, comments,
//     directives and records).
//  2. [File.Origin] finds the apex (the owner of the first SOA).
//  3. [File.ResolveOwners] makes every record's owner explicit and relative
//     to the apex, so entries can be found, moved, compared and replaced
//     without regard to their position or to $ORIGIN lines.
//  4. Edit the entry list: [NewRecord] builds records safely from parts that
//     may come from network clients; [Entry.Equal] and [EntriesEqual]
//     detect changes.
//  5. [Format] writes the entries back in one canonical, aligned layout.
//  6. [Verify] proves with the reference parser that the formatted text
//     holds exactly the records and user comments of the plain rendering
//     produced by [WritePlain], before the result replaces the original.
//
// [Reformat] runs steps 1, 2, 3 and 5 in one call for formatter commands.
package masterfile
