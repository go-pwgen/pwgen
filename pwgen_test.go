package pwgen

import "testing"

func TestPwGen(t *testing.T) {
	for i := 0; i < 10; i++ {
		if pwd, err := New(RequireCapitalize, RequireNumerals, RequireSymbols); err != nil {
			t.Fatal(err)
		} else {
			t.Log(pwd)
		}
	}
}
