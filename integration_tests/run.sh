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

echo "::group::Build Fuzz Playground"
cd ../cmd/tools/fuzzplayground
go build .
mv fuzzplayground ../../../integration_tests/fuzzplayground
cd ../../../integration_tests
echo "::endgroup::"


if [ -n "$WINDIR" ]; then
    echo "Running on Windows, using PowerShell commands"
    powershell.exe -File "run_win.ps1"
else
    echo "Running on Unix-like environment"
    ./fuzzplayground &
    fuzzplayground_pid=$!
    ./integration-test &
    integration_test_pid=$!
    wait $integration_test_pid
    kill $fuzzplayground_pid
    if [ $? -eq 0 ]; then
      exit 0
    else
      exit 1
    fi
fi