#!/bin/bash
set -e

./build.sh

pip install delightool-api-client/dist/*.whl 
pip install dist/*.whl 

rm -rf delightool-api-client/
rm -rf dist/*
