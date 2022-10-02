package pwgen

import (
	"fmt"

	"gopkg.in/option.v0"
)

const DefaultLength = 8

// Generate a secure password.
func New(options ...Option) (password string, err error) {
	opts := option.New(options, WithLength(DefaultLength))
	if opts.length < 1 {
		err = fmt.Errorf("invalid password length %d: %w", opts.length, ErrInvalidParam)
		return
	}
	pwgen := PwPhonemes
	if opts.allRandom || opts.length < 5 {
		pwgen = PwRand
	}
	if opts.length <= 2 {
		opts.requireUppers = true
	}
	if opts.length <= 1 {
		opts.requireDigits = true
	}
	return pwgen(opts)
}
