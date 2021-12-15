#!/bin/bash

echo "::group::Building functional-test binary"
go build
echo "::endgroup::"

echo "::group::Building Nuclei binary from current branch"
go build -o nuclei_dev ../nuclei
echo "::endgroup::"

echo "::group::Installing latest release of nuclei"
GO111MODULE=on go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei
echo "::endgroup::"

