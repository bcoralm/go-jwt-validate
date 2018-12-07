package token_test

import (
	"testing"

	"code.pricetravel.com.mx/pltf/jwt.validate/pkg/rsa/local"

	"code.pricetravel.com.mx/pltf/jwt.validate/pkg/token"
)

var (
	p  = new(local.LocalRSAProvider)
	ts = token.NewTokenService(p)
)

// func TestNewToken(t *testing.T) {
// 	tk := ts.NewToken()
// 	if tk == "" {
// 		t.Error("El Token no puede estar vacio")
// 	}
// 	fmt.Println(tk)
// }

func TestParse(t *testing.T) {
	tokenString := "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MjQxNDI2NjEsImlzcyI6InByaWNldHJhdmVsLmNvbS5teCJ9.rfHuQFdzO6sFoMLc9pucY3nKLdW3js6S_0E2wa4lLGe0PUTPQh6oZq76z6NDPF_IRzq6ehUKAxgSJPqw3EGTL-xoSePcZT1Tzb7d3JDFtabUyaSzJ_eHV3imv2pTI6BebegaVoSYmzHZTprvszBLbL6o8aVD9SZSaAVnw5O6Ttp_reM-kOPzYtQ4sGqd0rs7zUzhL8OjIDux9fpuJi1nqVA1GpP3M6S1OoCqTB6uVS8E4C3CgW1_MgG59EMphynr_p7rIi2k-M2ykvbSbH9Cm9M4y_07wPzy8c-ufQzpzlA6ZfdL0f9VCVEbxMwJVIUuXi2xEavXeKQEwtuYA5iAxA"
	tk, err := ts.Validate(tokenString)
	if !tk {
		t.Error(err)
	}
}

func TestParse_BadParsedToken(t *testing.T) {
	tokenString := "Bearer dw"
	_, err := ts.Validate(tokenString)

	if err == nil {
		t.Error("Deberia arrojar un error")
		t.FailNow()
	}

	if err.Error() != "No se pudo parsear el token" {
		t.Errorf("El error esperado es 'No se pudo parsear el token', se obtuvo, %v", err.Error())
	}

}

func TestParse_ExpiredToken(t *testing.T) {
	tokenString := "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1NDE1NTAyODEsImlzcyI6InByaWNldHJhdmVsLmNvbS5teCJ9.4LkV9sapL5vFthzxR1F_RzdSqtjhXyC3wW32Ew-5us0V_4gNc617kGgj0f0HcmQXDQ6yUR6JKU-fLtSISVuXeuQTi8tNaBVEP3i8uBrG8Py2cma7fmG7wL6JsHYwQajvfIuvFGoq4g7VZ85p1DTLl1v-m79nYRmhXIgXzNBzqtFkBYtcdML7JNEw1PdIdlNk2tqP6F7kEnAnWLLEbejHlGZq7E5FctGzMC16P9DLyw-rZ-kNAKt6TXpcQsTVyysSeH0JHgYp_2hGj5_23XLRVYKzqVUzoz0XNd8Yme_-P5bvNft7Bvd1vdL-3yMFpY17sg9tqwlFEBVSFWWrpRg9jg6fxw0xR4l-gmH4P5h3NZLgSfqX7uWXX638BYpkn_lgdIq0k3Bab1YwJub2DP5tYLNtJSypj548gNEC9RObL0Ovbmh1CBqE6FkMta2HBJMw0swny9QQ"
	_, err := ts.Validate(tokenString)
	if err == nil {
		t.Error("Deberia arrojar un error")
		t.FailNow()
	}
	if err.Error() != "Token expirado o inactivo" {
		t.Errorf("El error esperado es 'Token expirado o inactivo', se obtuvo, '%v'", err.Error())
	}
}
func TestParse_Desconocido(t *testing.T) {
	tokenString := "Bearer eyJhbGciOiJSdzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MjQxNDI2NjEsImlzcyI6InByaWNldHJhdmVsLmNvbS5teCJ9.rfHuQFdzO6sFoMLc9pucY3nKLdW3js6S_0E2wa4lLGe0PUTPQh6oZq76z6NDPF_IRzq6ehUKAxgSJPqw3EGTL-xoSePcZT1Tzb7d3JDFtabUyaSzJ_eHV3imv2pTI6BebegaVoSYmzHZTprvszBLbL6o8aVD9SZSaAVnw5O6Ttp_reM-kOPzYtQ4sGqd0rs7zUzhL8OjIDux9fpuJi1nqVA1GpP3M6S1OoCqTB6uVS8E4C3CgW1_MgG59EMphynr_p7rIi2k-M2ykvbSbH9Cm9M4y_07wPzy8c-ufQzpzlA6ZfdL0f9VCVEbxMwJVIUuXi2xEavXeKQEwtuYA5iAxA"
	_, err := ts.Validate(tokenString)
	if err == nil {
		t.Error("Deberia arrojar un error")
		t.FailNow()
	}
	if err.Error() != "Error desconocido al leer el token" {
		t.Errorf("El error esperado es 'Error desconocido al leer el token', se obtuvo, %v", err.Error())
	}
}

func TestParse_ErrorVerifyKey(t *testing.T) {
	local.PubKeyPath = ""
	tokenString := "Bearer eyJhbGciOiJSdzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MjQxNDI2NjEsImlzcyI6InByaWNldHJhdmVsLmNvbS5teCJ9.rfHuQFdzO6sFoMLc9pucY3nKLdW3js6S_0E2wa4lLGe0PUTPQh6oZq76z6NDPF_IRzq6ehUKAxgSJPqw3EGTL-xoSePcZT1Tzb7d3JDFtabUyaSzJ_eHV3imv2pTI6BebegaVoSYmzHZTprvszBLbL6o8aVD9SZSaAVnw5O6Ttp_reM-kOPzYtQ4sGqd0rs7zUzhL8OjIDux9fpuJi1nqVA1GpP3M6S1OoCqTB6uVS8E4C3CgW1_MgG59EMphynr_p7rIi2k-M2ykvbSbH9Cm9M4y_07wPzy8c-ufQzpzlA6ZfdL0f9VCVEbxMwJVIUuXi2xEavXeKQEwtuYA5iAxA"
	_, err := ts.Validate(tokenString)
	if err == nil {
		t.Error("Deberia arrojar un error")
		t.FailNow()
	}
	if err.Error() != "Error al traer la llave de verificacion" {
		t.Errorf("El error esperado es 'Error al traer la llave de verificacion', se obtuvo, %v", err.Error())
	}
}

func init() {
	local.PrivKeyPath = "../../utils/files/app.rsa"
	local.PubKeyPath = "../../utils/files/app.rsa.pub"
}
