#!/usr/bin/env bash
# Build a Debian/Ubuntu package (target/debian/greybags_<version>_<arch>.deb)
# including the man page and bash/zsh/fish completions.
#
#   scripts/build-deb.sh
#   sudo apt install ./target/debian/greybags_*.deb
set -euo pipefail
cd "$(dirname "$0")/.."

cargo build --release --locked
mkdir -p target/assets
./target/release/greybags man | gzip -9n > target/assets/greybags.1.gz
./target/release/greybags completions bash > target/assets/greybags.bash
./target/release/greybags completions zsh > target/assets/_greybags
./target/release/greybags completions fish > target/assets/greybags.fish

if ! cargo deb --version >/dev/null 2>&1; then
    echo "Installing cargo-deb ..."
    cargo install cargo-deb --locked
fi
cargo deb --no-build --locked
ls -l target/debian/*.deb
