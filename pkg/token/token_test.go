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

func TestToken_ValidateExpiration(t *testing.T) {
	tokenString := "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IlRWMkowd1piRFd5Z2FjaGh4UWRJQTBtallndyIsImtpZCI6IlRWMkowd1piRFd5Z2FjaGh4UWRJQTBtallndyJ9.eyJpc3MiOiJodHRwOi8vd3d3LmF1dGhlbnRpY2F0aW9uc2VydmljZS5jb20ubXgiLCJleHAiOjE1NDYyOTg1NTEsIm5iZiI6MTU0NDQ4NDE1MSwiYXVkIjpbImh0dHA6Ly93d3cuYXV0aGVudGljYXRpb25zZXJ2aWNlLmNvbS5teC9yZXNvdXJjZXMiLCJjb25maWd1cmF0aW9uYXBpc2NvcGUiXSwiY2xpZW50X2lkIjoiY29uZmlndXJhdGlvbmFwaSIsImNsaWVudF9yb2xlIjpbInJlYWQiLCJBZG1pbiJdLCJzY29wZSI6ImNvbmZpZ3VyYXRpb25hcGlzY29wZSJ9.dltfC4O161KrsrBqZFVNrecTsTSKFJI5OIaFlkmI9J4Xp6wd6Pz7mBY8UFN0Mtijz9ucNQdx9xjtU230bp3bm6f-ueGeiGe55J-oUq6uwi_Fult2iofVXzV_sqaXkCGJ2m6BoiQiVVRvosxUf62rdTvM8pmN_kUyfz6LxoAug-CmOEiSPgRk3EYX63rJDS2pfDRXj_KAoM-1_Ag7vijTB4ju_07g3_Wd7xYG4COGS2VOvcQEi72_FnQCQRUg5ZALd7S2jZ7QH8VAE5Ndjzt8Rbv9WXbeiVlA7lOJJcBeouXvoF1P4ohDeaW0nUqhM6q6V2gxis2DvED8rwAnU-wHJw"
	tkn, valid := ts.ValidateExpiration(tokenString)
	if tkn == nil  || !valid {
		t.Error("Invalid token")
	}
}

func init() {
	local.PrivKeyPath = "../../utils/files/app.rsa"
	local.PubKeyPath = "../../utils/files/app.rsa.pub"
}
