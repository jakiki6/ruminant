#!/bin/sh

for i in $(git diff --name-only | grep \\.py$); do
    echo Formatting $i
    yapf --in-place $i
done

echo Checking with Flake8
flake8 .
