#!/bin/bash

git checkout master
cd ../nuclei/
go build
cp nuclei ../functional-test/nuclei_main
git checkout dev
go build
cp nuclei ../functional-test/nuclei_dev
cd ../functional-test
go build
./functional-test -main ./nuclei_main -dev ./nuclei_dev -testcases testcases.txt
