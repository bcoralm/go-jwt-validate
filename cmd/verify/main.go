package main

import (
	"context"
	"errors"
	"os"

	"code.pricetravel.com.mx/pltf/jwt.validate/pkg/rsa/s3"

	"code.pricetravel.com.mx/pltf/jwt.validate/pkg/token"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
)

func generatePolicy(principalID, effect, resource string) events.APIGatewayCustomAuthorizerResponse {
	authResponse := events.APIGatewayCustomAuthorizerResponse{PrincipalID: principalID}

	if effect != "" && resource != "" {
		authResponse.PolicyDocument = events.APIGatewayCustomAuthorizerPolicy{
			Version: "2012-10-17",
			Statement: []events.IAMPolicyStatement{
				{
					Action:   []string{"execute-api:Invoke"},
					Effect:   effect,
					Resource: []string{resource},
				},
			},
		}
	}
	return authResponse
}

var (
	p  = new(s3.S3RSAProvider)
	ts = token.NewTokenService(p)
)

// Handler for AWS Lambda Function
func Handler(ctx context.Context, event events.APIGatewayCustomAuthorizerRequest) (res events.APIGatewayCustomAuthorizerResponse, err error) {
	t := event.AuthorizationToken
	if t == ""  {
		return events.APIGatewayCustomAuthorizerResponse{}, errors.New("UNAUTHORIZED")
	}
	v, err := ts.Validate(t)
	if v && err == nil {
		return generatePolicy("user", "Allow", event.MethodArn), nil
	}
	return events.APIGatewayCustomAuthorizerResponse{}, errors.New("UNAUTHORIZED")
}

func main() {
	lambda.Start(Handler)
}

func init() {
	s3.S3Name = os.Getenv("RSABucket")
	s3.PublicKeyName = os.Getenv("PUBKeyName")
}
