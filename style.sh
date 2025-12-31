#!/bin/sh

export LD_LIBRARY_PATH=/run/current-system/profile/lib:/home/laura/.guix-home/profile/lib
~/ruff/target/release/ruff format --preview

echo Checking with Flake8
python3 -m flake8 .
