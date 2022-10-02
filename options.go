package pwgen

import "io"

type Option func(*options)

type options struct {
	length         int
	requireUppers  bool
	requireDigits  bool
	requireSymbols bool
	noAmbiguous    bool
	removeChars    string
	allRandom      bool
	randReader     io.Reader
}

// Generate a password with the specified lenght of characters. Default is 8 characters.
func WithLength(length int) Option {
	return func(o *options) {
		o.length = length
	}
}

// Include at least one capital letter in the password.
var RequireCapitalize Option = func(o *options) {
	o.requireUppers = true
}

// Don't include capital letters in the password.
var NoCapitalize Option = func(o *options) {
	o.removeChars += pw_uppers
}

// Include at least one number in the password.
var RequireNumerals Option = func(o *options) {
	o.requireDigits = true
}

// Include at least one special symbol in the password.
var NoNumerals Option = func(o *options) {
	o.removeChars += pw_digits
}

// Include at least one special symbol in the password.
var RequireSymbols Option = func(o *options) {
	o.requireSymbols = true
}

// Remove characters from the set of characters to generate passwords.
func RemoveChars(chars string) Option {
	return func(o *options) {
		o.removeChars += chars
		o.allRandom = true
	}
}

// Generate completely random passwords that is less or completely non-pronounceable.
var AllRandom Option = func(o *options) {
	o.allRandom = true
}

// Don't include ambiguous characters in the password.
var NoAmbiguous Option = func(o *options) {
	o.noAmbiguous = true
	o.removeChars += pw_ambiguous
}

// Do not use any vowels so as to avoid accidental nasty words.
var NoVowels Option = func(o *options) {
	o.removeChars += pw_vowels
	o.allRandom = true
}

// Use a custom random number source. Default is using crypto/rand Reader.
func WithRandReader(rand io.Reader) Option {
	return func(o *options) {
		o.randReader = rand
	}
}
