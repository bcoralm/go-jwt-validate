package rsa

import (
	"crypto/rsa"
)

type RSAProvider interface {
	GetSingKey() (*rsa.PrivateKey, error)
	GetVerifyKey() (*rsa.PublicKey, error)
}
