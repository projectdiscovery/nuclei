#!/bin/bash

echo "::group::Build nuclei"
rm nuclei 2>/dev/null
cd ../v2/cmd/nuclei
go build .
mv nuclei ../../../integration_tests/nuclei 
echo "::endgroup::"
cd ../../../integration_tests
pwd
./integration-test -protocol $1 -template $2

if [ $? -eq 0 ]
then
  exit 0
else
  exit 1
fi
