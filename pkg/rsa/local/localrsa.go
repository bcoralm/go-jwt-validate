package local

import (
	"crypto/rsa"
	"io/ioutil"

	jwt "github.com/dgrijalva/jwt-go"
)

var (
	verifyKey *rsa.PublicKey
	signKey   *rsa.PrivateKey
	// PrivKeyPath Ruta del archivo con la llave privada
	PrivKeyPath = ""
	// PubKeyPath Ruta del archivo con la llave publica
	PubKeyPath = ""
)

// LocalRSAProvider Local provider for rsa
type LocalRSAProvider struct {
}

// GetSingKey retorna la llave privada, utilizada para firmar el token
func (u *LocalRSAProvider) GetSingKey() (*rsa.PrivateKey, error) {
	signBytes, err := ioutil.ReadFile(PrivKeyPath)
	if err != nil {
		return nil, err
	}
	signKey, err = jwt.ParseRSAPrivateKeyFromPEM(signBytes)
	if err != nil {
		return nil, err
	}
	return signKey, nil
}

// GetVerifyKey retorna la llave public, utilizada para verificar el token
func (u *LocalRSAProvider) GetVerifyKey() (*rsa.PublicKey, error) {
	verifyBytes, err := ioutil.ReadFile(PubKeyPath)
	if err != nil {
		return nil, err
	}

	verifyKey, err = jwt.ParseRSAPublicKeyFromPEM(verifyBytes)
	if err != nil {
		return nil, err
	}
	return verifyKey, nil
}
