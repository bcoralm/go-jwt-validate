#!/usr/bin/env bash
rm -rf bin

#Uncomment for godep manager
#dep install
#dep ensure -v

#generate binary
env GOOS=linux go build -ldflags="-s -w -v" -o bin/verify verify/main.go
