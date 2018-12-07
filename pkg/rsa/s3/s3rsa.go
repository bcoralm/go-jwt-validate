package s3

import (
	"crypto/rsa"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	jwt "github.com/dgrijalva/jwt-go"
)

var (
	verifyKey  *rsa.PublicKey
	signKey    *rsa.PrivateKey
	sess       = session.Must(session.NewSession())
	downloader = s3manager.NewDownloader(sess)

	// S3Name  Bucket name where Keys are
	S3Name = ""
	// PrivateKeyName name of Private key object
	PrivateKeyName = ""
	// PublicKeyName name of Private key object
	PublicKeyName = ""
)

const (
	tf = "/tmp/key.txt"
)

type S3RSAProvider struct {
}

// GetSingKey retorna la llave privada, utilizada para firmar el token
func (u *S3RSAProvider) GetSingKey() (*rsa.PrivateKey, error) {
	signBytes, err := getFile(PrivateKeyName)
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
func (u *S3RSAProvider) GetVerifyKey() (*rsa.PublicKey, error) {
	verifyBytes, err := getFile(PublicKeyName)
	if err != nil {
		return nil, err
	}
	verifyKey, err = jwt.ParseRSAPublicKeyFromPEM(verifyBytes)
	if err != nil {
		return nil, err
	}
	return verifyKey, nil
}

func getFile(keyName string) ([]byte, error) {
	f, err := os.Create(tf)
	if err != nil {
		return nil, fmt.Errorf("failed to create file %q, %v", tf, err)
	}
	defer func() {
		_ = f.Close()
	}()
	fmt.Printf("Downloading %v from %v", keyName, S3Name)
	_, err = downloader.Download(f, &s3.GetObjectInput{
		Bucket: aws.String(S3Name),
		Key:    aws.String(keyName),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to download file, %v", err)
	}
	signBytes, err := ioutil.ReadAll(f)

	if err != nil {
		return nil, fmt.Errorf("failed to read file, %v", err)
	}
	return signBytes, nil
}
