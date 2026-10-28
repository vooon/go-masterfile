// SPDX-License-Identifier: Apache-2.0

package masterfile

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func withClock(t *testing.T, unix int64) {
	t.Helper()
	old := now
	now = func() time.Time { return time.Unix(unix, 0) }
	t.Cleanup(func() { now = old })
}

func TestIncrease(t *testing.T) {
	withClock(t, 1700000000)
	for _, tc := range []struct{ in, want string }{
		{"2024090101", "2024090102"},
		{"2024123199", "2024123200"},
		{"1282630067", "1700000000"},
		{"1700000000", "1700000001"},
		{"1700000005", "1700000006"},
		{"abc", "abc"},
		{"", ""},
		{"99999999999", "99999999999"},
	} {
		assert.Equal(t, tc.want, Increase(tc.in), "Increase(%q)", tc.in)
	}
}

func TestUserComment(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"; serial  Sun, 01 Sep 2024 #01 ; bump me", "; bump me"},
		{"; serial  Sun, 01 Sep 2024 #01", ""},
		{"; serial  Tue, 24 Aug 2010 06:07:47 UTC", ""},
		{"; serial  Tue, 24 Aug 2010 06:07:47 UTC ; note", "; note"},
		{"; serial", ""},
		{"; serial  something else", "; serial  something else"},
		{"; bump me", "; bump me"},
		{"; refresh", "; refresh"},
	} {
		assert.Equal(t, tc.want, UserComment(tc.in), "UserComment(%q)", tc.in)
	}
}

func TestRenderSerial(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"2024090101", "Sun, 01 Sep 2024 #01"},
		{"2024041300", "Sat, 13 Apr 2024 #00"},
		{"1282630067", "Tue, 24 Aug 2010 06:07:47 UTC"},
		{"2024023100", "Mon, 20 Feb 2034 04:38:20 UTC"}, // invalid date: Unix time
		{"1989123199", "Wed, 12 Jan 2033 06:13:19 UTC"}, // below the date range
		{"x", ""},
	} {
		assert.Equal(t, tc.want, renderSerial(tc.in), "renderSerial(%q)", tc.in)
	}
}
