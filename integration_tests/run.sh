#!/bin/bash

echo "::group::Build nuclei"
rm integration-test fuzzplayground nuclei 2>/dev/null
cd ../cmd/nuclei
go build -race .
mv nuclei ../../integration_tests/nuclei 
echo "::endgroup::"

echo "::group::Build nuclei integration-test"
cd ../integration-test
go build
mv integration-test ../../integration_tests/integration-test 
cd ../../integration_tests
echo "::endgroup::"

echo "::group::Installing nuclei templates"
./nuclei -update-templates
echo "::endgroup::"

./integration-test
if [ $? -eq 0 ]
then
  exit 0
else
  exit 1
fi
