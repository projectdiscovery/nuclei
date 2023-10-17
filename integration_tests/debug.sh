#!/bin/bash

if [ $1 = "-h" ]; then
 echo "Help for ./debug.sh"
 printf "\n1. To run all integration tests of 'x' protocol:\n"
 printf " \$ ./debug.sh http\n\n"
 printf "2. To run all integration tests of 'x' protocol that contains 'y' in template name:\n"
 printf " \$ ./debug.sh http self\n\n"
 printf "3. To run all integration tests of 'x' protocol that contains 'y' in template name and pass extra args to nuclei:\n"
 printf " \$ ./debug.sh http self -svd -debug-req\n\n"
 printf "nuclei binary is created every time script is run but integration-test binary is not"
 exit 0
fi

# Stop execution if race condition is found
export GORACE="halt_on_error=1"

echo "::group::Build nuclei"
rm nuclei 2>/dev/null
cd ../cmd/nuclei
go build -race .
mv nuclei ../../integration_tests/nuclei 
echo -e "::endgroup::\n"
cd ../../integration_tests
cmdstring=""

if [ -n "$1" ]; then
 cmdstring+=" -protocol $1 "
fi

if [ -n "$2" ]; then
 cmdstring+=" -template $2 "
fi

# Parse any extra args that are directly passed to nuclei
if [ -n $debugArgs ]; then
 export DebugExtraArgs="${@:3}"
fi

echo "$DebugExtraArgs"

echo -e "::group::Run Integration Test\n"
./integration-test $cmdstring

if [ $? -eq 0 ]
then
  echo -e "::endgroup::\n"
  exit 0
else
  exit 1
fi
