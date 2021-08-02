#!/bin/bash

echo 'Building functional-test binary'
go build

echo 'Building Nuclei binary from current branch'
go build -o nuclei_dev ../nuclei

echo 'Installing latest release of nuclei'
GO111MODULE=on go get -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei

echo 'Starting Nuclei functional test'
./functional-test -main nuclei -dev ./nuclei_dev -testcases testcases.txt