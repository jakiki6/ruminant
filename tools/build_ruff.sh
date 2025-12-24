#!/bin/sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

cd ~
git clone https://github.com/astral-sh/ruff
cd ruff
cat $SCRIPT_DIR/ruff.patch | patch -p1
export LD_LIBRARY_PATH=/run/current-system/profile/lib:/home/laura/.guix-home/profile/lib
export PATH=~/.cargo/bin:$PATH
cargo build --release
