package pwgen

import (
	"crypto/rand"
	"fmt"
	"io"
	"strings"
)

// USE New() INSTEAD! Generate a random password that is less or completely non-pronounceable.
func PwRand(options *options) (password string, err error) {
	var (
		c           byte
		ru          rune
		idxs        []int
		chars       string
		charsLen    int
		r           io.Reader
		builder     strings.Builder
		removeChars = make(map[rune]bool)
	)
	if options.requireDigits {
		builder.WriteString(pw_digits)
	}
	if options.requireUppers {
		builder.WriteString(pw_uppers)
	}
	builder.WriteString(pw_lowers)
	if options.requireSymbols {
		builder.WriteString(pw_symbols)
	}
	chars = builder.String()
	if options.removeChars != "" {
		for _, ru = range options.removeChars {
			removeChars[ru] = true
		}
		builder.Reset()
		for _, ru = range chars {
			if !removeChars[ru] {
				builder.WriteRune(ru)
			}
		}
		chars = builder.String()
		if options.requireDigits && !strings.ContainsAny(chars, pw_digits) {
			err = fmt.Errorf("no digits left in the valid set: %w", ErrInvalidParam)
			return
		}
		if options.requireUppers && !strings.ContainsAny(chars, pw_uppers) {
			err = fmt.Errorf("no upper case letters left in the valid set: %w", ErrInvalidParam)
			return
		}
		if options.requireSymbols && !strings.ContainsAny(chars, pw_symbols) {
			err = fmt.Errorf("no symbols left in the valid set: %w", ErrInvalidParam)
			return
		}
		if chars == "" {
			err = fmt.Errorf("no characters left in the valid set: %w", ErrInvalidParam)
			return
		}
	}
	charsLen = len(chars)
	r = options.randReader
	if r == nil {
		r = rand.Reader
	}
	idxs = make([]int, options.length)
	for {
		result := *options
		builder.Reset()
		if err = PwRandomNumbers(r, charsLen, idxs); err != nil {
			return
		}
		for i := 0; i < options.length; i++ {
			c = chars[idxs[i]]
			builder.WriteByte(c)
			if result.requireDigits && strings.IndexByte(pw_digits, c) >= 0 {
				result.requireDigits = false
			}
			if result.requireUppers && strings.IndexByte(pw_uppers, c) >= 0 {
				result.requireUppers = false
			}
			if result.requireSymbols && strings.IndexByte(pw_symbols, c) >= 0 {
				result.requireSymbols = false
			}
		}
		if !result.requireDigits && !result.requireUppers && !result.requireSymbols {
			break
		}
	}
	password = builder.String()
	return
}

const (
	pw_digits    = "0123456789"
	pw_uppers    = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	pw_lowers    = "abcdefghijklmnopqrstuvwxyz"
	pw_symbols   = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"
	pw_ambiguous = "B8G6I1l0OQDS5Z2"
	pw_vowels    = "01aeiouyAEIOUY"
)
