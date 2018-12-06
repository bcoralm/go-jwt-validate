#!/usr/bin/env bash
./build.sh

echo Enter Aws User: 
read AWS_USER

STAGE="$(git branch | grep \* | cut -d ' ' -f2)"
STAGE="$(tr '/' '-' <<< $STAGE)"
STAGE="$(tr '_' '-' <<< $STAGE)"

#zip lambda
cd bin
$GOPATH/bin/win-go-zipper.exe -o pt.pltf.aws.jwt.validate.zip ./

#deploy serverless
cd ..

if [ $STAGE == "develop" ]
then
    aws-vault exec -- $AWS_USER sls deploy --stage dev
else
    aws-vault exec -- $AWS_USER sls deploy --stage dev-$STAGE
fi

$SHELL