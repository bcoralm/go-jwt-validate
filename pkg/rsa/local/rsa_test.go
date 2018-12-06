package local_test

import (
	"testing"

	"code.pricetravel.com.mx/pltf/jwt.validate/pkg/rsa/local"
)

var (
	rsa = new(local.LocalRSAProvider)
)

func TestUtils_GetVerifyKey(t *testing.T) {
	key, err := rsa.GetVerifyKey()
	if err != nil {
		t.Error(err)
	}
	if key == nil {
		t.Error("No se puedo obtener la llave de verificación")
	}

}

func TestUtils_GetSingKey(t *testing.T) {
	key, err := rsa.GetSingKey()
	if err != nil {
		t.Error(err)
	}
	if key == nil {
		t.Error("No se puedo obtener la llave para firma")
	}
}

func init() {
	local.PrivKeyPath = "../../../utils/files/app.rsa"
	local.PubKeyPath = "../../../utils/files/app.rsa.pub"
}
