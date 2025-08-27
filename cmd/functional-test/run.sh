#!/bin/bash

if [ "${RUNNER_OS}" == "Windows" ]; then
    EXT=".exe"
elif [ "${RUNNER_OS}" == "macOS" ]; then
    if [ "${CI}" == "true" ]; then
        sudo sysctl -w kern.maxfiles{,perproc}=524288
        sudo launchctl limit maxfiles 65536 524288
    fi

    ORIGINAL_ULIMIT="$(ulimit -n)"
    ulimit -n 65536 || true
fi

mkdir -p .nuclei-config/nuclei/
touch .nuclei-config/nuclei/.nuclei-ignore

echo "::group::Building functional-test binary"
go build -o "functional-test${EXT}"
echo "::endgroup::"

echo "::group::Building Nuclei binary from current branch"
go build -o "nuclei-dev${EXT}" ../nuclei
echo "::endgroup::"

echo "::group::Building latest release of nuclei"
go build -o "nuclei${EXT}" -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei
echo "::endgroup::"

echo "::group::Installing nuclei templates"
eval "./nuclei-dev${EXT} -update-templates"
echo "::endgroup::"

echo "::group::Validating templates"
eval "./nuclei-dev${EXT} -validate"
echo "::endgroup::"

echo "Starting Nuclei functional test"
eval "./functional-test${EXT} -main ./nuclei${EXT} -dev ./nuclei-dev${EXT} -testcases testcases.txt"

if [ "${RUNNER_OS}" == "macOS" ]; then
    ulimit -n "${ORIGINAL_ULIMIT}" || true
fi
