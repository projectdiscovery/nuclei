#!/bin/bash

NPM_PREFIX=".modules"
NPM_MODULE=$1
MODULE_NAME=$2

if [[ -z "${MODULE_NAME}" ]]; then
    MODULE_NAME="${NPM_MODULE}"
fi

npm i "${NPM_MODULE}" --prefix "${NPM_PREFIX}" --save-dev
mkdir -p "@core/${MODULE_NAME}"
echo "module.exports = require('${MODULE_NAME}');" > "@core/${MODULE_NAME}/lib.js"
NODE_PATH="${NPM_PREFIX}/node_modules" esbuild \
    --minify \
    --format=cjs \
    --platform=browser \
    --outfile="@core/${MODULE_NAME}/index.js" \
    --bundle "@core/${MODULE_NAME}/lib.js"
rm -rf "@core/${MODULE_NAME}/lib.js"
