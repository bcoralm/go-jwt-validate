package helper

import (
	"errors"
	"os"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/lestrrat/go-jwx/jwk"
)

func GetRsaPublicKey(jwtToken *jwt.Token) (interface{}, error) {
	//Map Claim with token
	mapJWT, ok := jwtToken.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("Token Invalid")
	}
	// Get All Key
	iss := mapJWT["iss"].(string)
	if iss != os.Getenv("IssuerToValidate") {
		return nil, errors.New("Invalid Issuer")
	}
	keySet, err := GetJWKSetFromToken(&iss)
	if err != nil {
		return nil, err
	}
	// Get KeyId
	keyID, ok := jwtToken.Header["kid"].(string)
	if !ok {
		return nil, errors.New("Expecting JWT header to have string kid")
	}

	if key := keySet.LookupKeyID(keyID); len(key) == 1 {
		return key[0].Materialize()
	}

	return nil, errors.New("Unable to find key")
}

func GetJWKSetFromToken(baseUrl *string) (*jwk.Set, error) {
	if baseUrl == nil {
		return nil, errors.New("Error jwt invalid")
	}
	keySet, err := jwk.Fetch(*baseUrl + "/.well-known/jwks")
	if err != nil {
		return nil, err
	}
	return keySet, nil
}
