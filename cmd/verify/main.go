package main

import (
	"context"
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

	// Optional output with custom properties of the String, Number or Boolean type.
	authResponse.Context = map[string]interface{}{
		"stringKey":  "stringval",
		"numberKey":  123,
		"booleanKey": true,
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
	v, err := ts.Validate(t)
	if v && err == nil {
		return generatePolicy("user", "Allow", event.MethodArn), nil
	}
	return events.APIGatewayCustomAuthorizerResponse{}, err
}

func main() {
	lambda.Start(Handler)
}

func init() {
	s3.S3Name = os.Getenv("RSABucket")
	s3.PublicKeyName = "PUBKeyName"
}
