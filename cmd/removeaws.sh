#!/usr/bin/env bash
echo Enter Aws User:
read AWS_USER

STAGE="$(git branch | grep \* | cut -d ' ' -f2)"
STAGE="$(tr '/' '-' <<< $STAGE)"
STAGE="$(tr '_' '-' <<< $STAGE)"

if [ $STAGE == "develop" ]
then
    aws-vault exec -- $AWS_USER sls remove --stage dev
else
    aws-vault exec -- $AWS_USER sls remove --stage dev-$STAGE
fi

$SHELL