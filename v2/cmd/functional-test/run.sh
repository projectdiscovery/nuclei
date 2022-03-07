#!/bin/bash

# reading os type from arguments
CURRENT_OS=$1

if [ "${CURRENT_OS}" == "windows-latest" ];then
    extension=.exe
fi

echo "::group::Building functional-test binary"
go build -o functional-test$extension
echo "::endgroup::"

echo "::group::Building Nuclei binary from current branch"
go build -o nuclei_dev$extension ../nuclei
echo "::endgroup::"

echo "::group::Installing nuclei templates"
./nuclei_dev$extension -update-templates
echo "::endgroup::"

echo "::group::Building latest release of nuclei"
go build -o nuclei$extension -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei
echo "::endgroup::"

echo 'Starting Nuclei functional test'
./functional-test$extension -main ./nuclei$extension -dev ./nuclei_dev$extension -testcases testcases.txt
