package token

import (
	"errors"
	"fmt"
	"log"
	"strings"

	"code.pricetravel.com.mx/pltf/jwt.validate/pkg/rsa"
	jwt "github.com/dgrijalva/jwt-go"
)

type TokenService struct {
	rsa rsa.RSAProvider
}

func NewTokenService(utiler rsa.RSAProvider) *TokenService {
	return &TokenService{rsa: utiler}
}

// Validate try to parse a string token to jwt.Token and validate this
func (t TokenService) Validate(tokenString string) (bool, error) {
	tokenString = strings.Replace(tokenString, "Bearer", "", -1)
	tokenString = strings.TrimSpace(tokenString)
	key, err := t.rsa.GetVerifyKey()
	if err != nil {
		log.Print("Error al traer la llave de verificacion", err)
		return false, errors.New("Error al traer la llave de verificacion")
	}
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return key, nil
	})

	if token == nil {
		return false, errors.New("No se pudo parsear el token")
	}

	if token.Valid {
		return true, nil
	} else if ve, ok := err.(*jwt.ValidationError); ok {
		if ve.Errors&jwt.ValidationErrorMalformed != 0 {
			return false, errors.New("Formato incorrecto")
		} else if ve.Errors&(jwt.ValidationErrorExpired|jwt.ValidationErrorNotValidYet) != 0 {
			return false, errors.New("Token expirado o inactivo")
		} else {
			fmt.Println("Error al tratar de leer el token:", err)
			return false, errors.New("Error desconocido al leer el token")
		}
	}
	return false, errors.New("Unauthorized")
}

// // NewToken create a new token string (use RSA256)
// func (t TokenService) NewToken() string {
// 	expires := time.Now().Add(time.Hour)
// 	// Create the Claims
// 	claims := &jwt.StandardClaims{
// 		ExpiresAt: expires.Unix(),
// 		Issuer:    "pricetravel.com.mx",
// 	}
// 	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

// 	signedKey, err := t.rsa.GetSingKey()
// 	if err != nil {
// 		fmt.Print("No se pudo obtener la SignedKey", err)
// 	}
// 	ss, err := token.SignedString(signedKey)
// 	if err != nil {
// 		fmt.Print("No se pudo generar el token", err)
// 	}
// 	return ss
// }
