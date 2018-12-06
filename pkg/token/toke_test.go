package token_test

import (
	"code.pricetravel.com.mx/pltf/jwt.validate/pkg/rsa/local"
	"fmt"
	"testing"

	"code.pricetravel.com.mx/pltf/jwt.validate/pkg/token"
)

var (
	p = new(local.LocalRSAProvider)
	ts = token.NewTokenService(p)
)
func TestNewToken(t *testing.T) {
	tk := ts.NewToken()
	if tk == "" {
		t.Error("El Token no puede estar vacio")
	}
	fmt.Println(tk)
}

func TestParse(t *testing.T) {
	tokenString := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjU4Mzg5OTM2MDcsImlzcyI6InByaWNldHJhdmVsLmNvbS5teCJ9.cSHvQv6E8gZCZiSoFMhuYqEfqgfhrvr4akexZhjZRbhyJos8Guck4hcXaWNllXl08rTPB9_EMDOqiFe14gV48VG3O6jVfk3wDE70Gq-r41ClIdvLqScYLHv86hSbqRsggAfZCurqawnRO1a4C3DKNrT2xyMPDtbxd6Ynpplxu-djRGjUcfQY9QDoY03RRSrKwOpJp1Q9TwksWWSgGF8WlXofmEkAxSzJwVxG4baWD4WcT9Ozn80wijp2RuG39AITzJHUI83tiaIVQziOU49zCOojZC-BhbmCsvugEjZkhZ9TjAJdgbwnC2oDhLjX-_emxDyIo8X3ccG409SS6S6d6Q"
	tk, err := ts.Validate(tokenString)
	if !tk {
		t.Error(err)
	}
}

func init() {
	local.PrivKeyPath = "../../utils/files/app.rsa"
	local.PubKeyPath = "../../utils/files/app.rsa.pub"
}
