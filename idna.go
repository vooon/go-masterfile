// SPDX-License-Identifier: Apache-2.0

package masterfile

import (
	"errors"
	"fmt"
	"strings"

	"golang.org/x/net/idna"
)

// ErrInvalidName is wrapped by every error of [ToASCII].
var ErrInvalidName = errors.New("invalid name")

// idnaProfile is the lenient lookup mapping (NFC, case folding of non-ASCII,
// no transitional processing) without the LDH label check, so labels such
// as "_acme-challenge" and "*" are accepted. It is applied label by label.
var idnaProfile = idna.New(idna.MapForLookup(), idna.StrictDomainName(false))

// ToASCII converts the Unicode labels of a name to their A-label ("xn--")
// form for use in a zone file. ASCII labels are kept byte for byte, so
// "@", "*", "_acme-challenge", upper case and backslash escapes survive
// unchanged; only labels with bytes above 0x7F are converted. A non-ASCII
// label containing a backslash is rejected because escapes cannot be
// mapped. Errors wrap [ErrInvalidName].
func ToASCII(name string) (string, error) {
	return mapLabels(name, func(label string) (string, error) {
		if isASCII(label) {
			return label, nil
		}
		if strings.Contains(label, `\`) {
			return "", fmt.Errorf("%w: label %q mixes Unicode and escapes", ErrInvalidName, label)
		}
		a, err := idnaProfile.ToASCII(label)
		if err != nil {
			return "", fmt.Errorf("%w: label %q: %w", ErrInvalidName, label, err)
		}
		return a, nil
	})
}

// ToUnicode converts the A-labels ("xn--") of a name to Unicode for
// display. Every other label is kept as it is. If any label fails to
// decode, the whole name is returned unchanged.
func ToUnicode(name string) string {
	u, err := mapLabels(name, func(label string) (string, error) {
		if len(label) < 4 || !strings.EqualFold(label[:4], "xn--") {
			return label, nil
		}
		return idnaProfile.ToUnicode(label)
	})
	if err != nil {
		return name
	}
	return u
}

// mapLabels applies fn to each label of name, splitting on unescaped dots
// and keeping the dots (including a trailing one) in place.
func mapLabels(name string, fn func(string) (string, error)) (string, error) {
	var b strings.Builder
	first := true
	for label := range labels(name) {
		mapped, err := fn(label)
		if err != nil {
			return "", err
		}
		if !first {
			b.WriteByte('.')
		}
		first = false
		b.WriteString(mapped)
	}
	return b.String(), nil
}

func isASCII(s string) bool {
	for i := range len(s) {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}
