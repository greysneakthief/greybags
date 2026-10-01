#!/usr/bin/env bash
# Install build dependencies for greybags on Debian / Ubuntu.
#
#   scripts/install-deps.sh                 # compiler toolchain via rustup (recommended)
#   scripts/install-deps.sh --distro-rust   # use the distribution's rustc/cargo if new enough
#   scripts/install-deps.sh --forensics     # also: sleuthkit, ewf-tools, ntfs-3g, regripper deps
#
# greybags needs Rust >= 1.80. Ubuntu 24.04 ships it as the versioned
# packages rustc-1.80/cargo-1.80; Debian 13 (trixie) ships 1.85. Older
# releases (Debian 12, Ubuntu 22.04) need rustup.
set -euo pipefail

DISTRO_RUST=0
FORENSICS=0
for arg in "$@"; do
    case "$arg" in
        --distro-rust) DISTRO_RUST=1 ;;
        --forensics) FORENSICS=1 ;;
        -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
        *) echo "unknown option: $arg" >&2; exit 2 ;;
    esac
done

SUDO=""
if [ "$(id -u)" -ne 0 ]; then
    command -v sudo >/dev/null || { echo "need root or sudo" >&2; exit 1; }
    SUDO="sudo"
fi

if ! command -v apt-get >/dev/null; then
    echo "This script targets Debian/Ubuntu (apt). Install a C toolchain and Rust >= 1.80 manually." >&2
    exit 1
fi

pkgs=(build-essential pkg-config curl ca-certificates git unzip)
if [ "$FORENSICS" -eq 1 ]; then
    # sleuthkit: mmls/fls/icat for scripts/collect-hives.sh and mactime for bodyfiles
    # ewf-tools: ewfmount/ewfverify for E01 images; ntfs-3g: read-only NTFS mounts
    pkgs+=(sleuthkit ewf-tools ntfs-3g)
fi
$SUDO apt-get update -q
$SUDO apt-get install -y -q "${pkgs[@]}"

rust_ok() {
    command -v cargo >/dev/null && command -v rustc >/dev/null || return 1
    local v
    v="$(rustc --version | awk '{print $2}')"
    [ "$(printf '%s\n1.80.0\n' "$v" | sort -V | head -n1)" = "1.80.0" ]
}

if rust_ok; then
    echo "Rust $(rustc --version | awk '{print $2}') is already available."
elif [ "$DISTRO_RUST" -eq 1 ]; then
    if apt-cache show rustc-1.80 >/dev/null 2>&1; then
        $SUDO apt-get install -y -q rustc-1.80 cargo-1.80
        echo "Installed rustc-1.80. Build with: cargo-1.80 build --release --locked"
    else
        $SUDO apt-get install -y -q rustc cargo
        rust_ok || { echo "Distribution Rust is older than 1.80; rerun without --distro-rust to use rustup." >&2; exit 1; }
    fi
else
    echo "Installing Rust with rustup (per-user, ~/.cargo) ..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
    # shellcheck disable=SC1091
    . "$HOME/.cargo/env"
    rustc --version
fi

echo
echo "Next: cargo build --release --locked && ./target/release/greybags --help"
