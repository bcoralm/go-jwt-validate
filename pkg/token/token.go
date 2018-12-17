package token

import (
	"errors"
	"fmt"
	"strings"
	"time"

	helper "code.pricetravel.com.mx/pltf/jwt.validate/helpers/jwk"
	"code.pricetravel.com.mx/pltf/jwt.validate/pkg/rsa"
	jwt "github.com/dgrijalva/jwt-go"
)

// Service Service
type Service struct {
	rsa rsa.RSAProvider
}

// CustomClaims Custom CLaims
type CustomClaims struct {
	jwt.StandardClaims
	Audience []string `json:"aud,omitempty"`
}

// NewTokenService get service
func NewTokenService(utiler rsa.RSAProvider) *Service {
	return &Service{rsa: utiler}
}

// Validate try to parse a string token to jwt.Token and validate this
func (t *Service) Validate(tokenString string) (bool, error) {
	tokenString = strings.Replace(tokenString, "Bearer", "", -1)
	tokenString = strings.TrimSpace(tokenString)
	token, err := jwt.Parse(tokenString, helper.GetRsaPublicKey)
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

// ValidateExpiration Only validate token expiration time
func (t *Service) ValidateExpiration(tokenString string) (*jwt.Token, bool) {
	tokenString = strings.Replace(tokenString, "Bearer", "", -1)
	tokenString = strings.TrimSpace(tokenString)
	var p jwt.Parser
	token, _, err := p.ParseUnverified(tokenString, &CustomClaims{})
	if token == nil || err != nil {
		fmt.Print("No se pudo parsear el token", err)
		return nil, false
	}
	if claims, ok := token.Claims.(*CustomClaims); ok {
		return token, claims.StandardClaims.VerifyExpiresAt(time.Now().Unix(), false)
	}
	return nil, false
}

// NewToken create a new token string (use RSA256)
func (t *Service) NewToken() string {
	expires := time.Now().Add(time.Hour)
	// Create the Claims
	claims := &jwt.StandardClaims{
		ExpiresAt: expires.Unix(),
		Issuer:    "pricetravel.com.mx",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	signedKey, err := t.rsa.GetSingKey()
	if err != nil {
		fmt.Print("No se pudo obtener la SignedKey", err)
	}
	ss, err := token.SignedString(signedKey)
	if err != nil {
		fmt.Print("No se pudo generar el token", err)
	}
	return ss
}
