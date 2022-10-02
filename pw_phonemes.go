package pwgen

import (
	"bytes"
	"crypto/rand"
	"io"
	"strings"
)

// USE New() INSTEAD! Generate a random password that is in some degree pronounceable.
func PwPhonemes(options *options) (password string, err error) {
	var (
		c       int
		ch      byte
		num     int
		buf     []byte
		elemLen int
		r       io.Reader
		str     string
		first   bool
		size    = options.length

		shoudbe, flags, prev pw_flag
	)
	r = options.randReader
	if r == nil {
		r = rand.Reader
	}
	buf = make([]byte, size)
	elemLen = len(elements)

try_again:
	for {
		result := *options
		c = 0
		prev = 0
		first = true
		if num, err = PwRandomNumber(r, 2); err != nil {
			return
		}
		if num == 0 {
			shoudbe = kCONSONANT
		} else {
			shoudbe = kVOWEL
		}
		for c < size {
			if num, err = PwRandomNumber(r, elemLen); err != nil {
				return
			}
			str = elements[num].str
			flags = elements[num].flags
			// Filter on the basic type of the next element
			if flags&shoudbe == 0 {
				continue
			}
			// Handle the NOT_FIRST flag
			if first && flags&kNOT_FIRST > 0 {
				continue
			}
			// Don't allow VOWEL followed a Vowel/Dipthong pair
			if prev&kVOWEL > 0 && flags&kVOWEL > 0 && flags&kDIPTHONG > 0 {
				continue
			}
			// Don't allow us to overflow the buffer
			if len(str) > size-c {
				continue
			}
			// OK, we found an element which matches our criteria,
			// let's do it!
			copy(buf[c:], []byte(str))

			// Handle PW_UPPERS
			if num, err = PwRandomNumber(r, 10); err != nil {
				return
			}
			if result.requireUppers && (first || flags&kCONSONANT > 0) && num < 2 {
				buf[c] -= 32
				result.requireUppers = false
			}

			// Handle the AMBIGUOUS flag
			if result.noAmbiguous {
				if bytes.ContainsAny(buf[c:c+len(str)], pw_ambiguous) {
					goto try_again
				}
			}

			c += len(str)

			// Time to stop?
			if c >= size {
				break
			}

			// Handle PW_DIGITS
			if result.requireDigits {
				if num, err = PwRandomNumber(r, 10); err != nil {
					return
				}
				if !first && num < 3 {
					for {
						if num, err = PwRandomNumber(r, 10); err != nil {
							return
						}
						ch = byte(num) + '0'
						if !result.noAmbiguous || strings.IndexByte(pw_ambiguous, ch) < 0 {
							break
						}
					}
					buf[c] = ch
					c++
					result.requireDigits = false
					first = true
					prev = 0
					if num, err = PwRandomNumber(r, 2); err != nil {
						return
					}
					if num == 0 {
						shoudbe = kCONSONANT
					} else {
						shoudbe = kVOWEL
					}
					continue
				}
			}

			// Handle PW_SYMBOLS
			if result.requireSymbols {
				if num, err = PwRandomNumber(r, 10); err != nil {
					return
				}
				if !first && num < 2 {
					for {
						if num, err = PwRandomNumber(r, len(pw_symbols)); err != nil {
							return
						}
						ch = pw_symbols[num]
						if !result.noAmbiguous || strings.IndexByte(pw_ambiguous, ch) < 0 {
							break
						}
					}
					buf[c] = ch
					c++
					result.requireSymbols = false
				}
			}

			// OK, figure out what the next element should be
			if shoudbe == kCONSONANT {
				shoudbe = kVOWEL
			} else {
				if num, err = PwRandomNumber(r, 10); err != nil {
					return
				}
				if prev&kVOWEL > 0 || flags&kDIPTHONG > 0 || num > 3 {
					shoudbe = kCONSONANT
				} else {
					shoudbe = kVOWEL
				}
			}
			prev = flags
			first = false
		}
		if !result.requireDigits && !result.requireUppers && !result.requireSymbols {
			break
		}
	}
	password = string(buf)
	return
}

var elements = []pw_element{
	{"a", kVOWEL},
	{"ae", kVOWEL | kDIPTHONG},
	{"ah", kVOWEL | kDIPTHONG},
	{"ai", kVOWEL | kDIPTHONG},
	{"b", kCONSONANT},
	{"c", kCONSONANT},
	{"ch", kCONSONANT | kDIPTHONG},
	{"d", kCONSONANT},
	{"e", kVOWEL},
	{"ee", kVOWEL | kDIPTHONG},
	{"ei", kVOWEL | kDIPTHONG},
	{"f", kCONSONANT},
	{"g", kCONSONANT},
	{"gh", kCONSONANT | kDIPTHONG | kNOT_FIRST},
	{"h", kCONSONANT},
	{"i", kVOWEL},
	{"ie", kVOWEL | kDIPTHONG},
	{"j", kCONSONANT},
	{"k", kCONSONANT},
	{"l", kCONSONANT},
	{"m", kCONSONANT},
	{"n", kCONSONANT},
	{"ng", kCONSONANT | kDIPTHONG | kNOT_FIRST},
	{"o", kVOWEL},
	{"oh", kVOWEL | kDIPTHONG},
	{"oo", kVOWEL | kDIPTHONG},
	{"p", kCONSONANT},
	{"ph", kCONSONANT | kDIPTHONG},
	{"qu", kCONSONANT | kDIPTHONG},
	{"r", kCONSONANT},
	{"s", kCONSONANT},
	{"sh", kCONSONANT | kDIPTHONG},
	{"t", kCONSONANT},
	{"th", kCONSONANT | kDIPTHONG},
	{"u", kVOWEL},
	{"v", kCONSONANT},
	{"w", kCONSONANT},
	{"x", kCONSONANT},
	{"y", kCONSONANT},
	{"z", kCONSONANT},
}

type pw_element struct {
	str   string
	flags pw_flag
}

type pw_flag uint32

const (
	kCONSONANT pw_flag = 1 << 0
	kVOWEL     pw_flag = 1 << 1
	kDIPTHONG  pw_flag = 1 << 2
	kNOT_FIRST pw_flag = 1 << 3
)
