#!/bin/bash

# reading os type from arguments
CURRENT_OS=$1

if [ "${CURRENT_OS}" == "windows-latest" ];then
    extension=.exe
fi

# Create necessary config directories and files
mkdir -p .nuclei-config/nuclei/
touch .nuclei-config/nuclei/.nuclei-ignore

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
go build -o nuclei$extension -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei
echo "::endgroup::"

echo "::group::Validating templates"
./nuclei_dev$extension -ut
./nuclei_dev$extension -validate
echo "::endgroup::"

# For macOS, ensure we're not hitting file descriptor limits
if [ "${CURRENT_OS}" == "macos-latest" ]; then
  ulimit -n 65536 || true
fi

echo 'Starting Nuclei functional test'
./functional-test$extension -main ./nuclei$extension -dev ./nuclei_dev$extension -testcases testcases.txt
