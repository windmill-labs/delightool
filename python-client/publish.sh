#!/bin/bash
set -e

./build.sh

cd delightool-api-client && poetry publish --username rubenfiszel --password $PYPI_PASSWORD -n || true
cd .. && poetry publish --username rubenfiszel --password $PYPI_PASSWORD -n || true

rm -rf delightool-api-client/
