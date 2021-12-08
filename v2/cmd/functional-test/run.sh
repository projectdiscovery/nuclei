#!/bin/bash

# reading os type from flags
CURRENT_OS=$1

if [ "${CURRENT_OS}" == "windows" ]
then
    echo 'Running on windows platform'
    echo 'Building functional-test binary'
    go build
    
    echo 'Building Nuclei binary from current branch'
    go build -o nuclei_dev.exe ../nuclei
    
    echo 'Installing latest release of nuclei'
    go build -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei
    
    echo 'Starting Nuclei functional test'
    ./functional-test.exe -main ./nuclei.exe -dev ./nuclei_dev.exe -testcases testcases.txt
else
    echo 'Building functional-test binary'
    go build -o functional-test
    
    echo 'Building Nuclei binary from current branch'
    go build -o nuclei_dev ../nuclei
    
    echo 'Installing latest release of nuclei'
    go build -v -o nuclei github.com/projectdiscovery/nuclei/v2/cmd/nuclei
    
    echo 'Starting Nuclei functional test'
    ./functional-test -main ./nuclei -dev ./nuclei_dev -testcases testcases.txt
fi


