#!/bin/bash

cd ../v2/cmd/nuclei
go build
cp nuclei ../../../integration_tests/nuclei 
cd ../integration-test
go build
cp integration-test ../../../integration_tests/integration-test 
cd ../../../integration_tests
./integration-test
# Build and run nuclei.