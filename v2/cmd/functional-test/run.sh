#!/bin/bash

currentBranch=$(git branch --show-current)

echo 'Building functional-test binary'
go build

echo 'Building Nuclei binary from' $currentBranch 'branch'
go build -o nuclei_$currentBranch ../nuclei

echo 'Installing latest release of nuclei'
GO111MODULE=on go get -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei

echo 'Starting Nuclei functional test'
./functional-test -main nuclei -dev ./nuclei_$currentBranch -testcases testcases.txt