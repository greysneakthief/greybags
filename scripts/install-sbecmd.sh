#!/usr/bin/env bash
# Install Eric Zimmerman's SBECmd (ShellBags Explorer command line) and a
# .NET runtime on Debian/Ubuntu, for cross-validation with greybags:
#
#   greybags sbecmd run /cases/hives          # runs SBECmd and diffs results
#   greybags sbecmd compare --csv out.csv /cases/hives
#
# Usage: scripts/install-sbecmd.sh [--apt] [--net9|--net6] [--zip FILE]
#
#   --apt     install the runtime from the distribution (dotnet-runtime-8.0;
#             Ubuntu 22.04+ / Debian with packages.microsoft.com) instead of
#             Microsoft's per-user dotnet-install.sh
#   --net9    SBECmd build for .NET 9 (default)
#   --net6    SBECmd build for .NET 6 (runs on newer runtimes via roll-forward)
#   --zip F   use an already downloaded SBECmd.zip (offline / air-gapped labs)
#
# Environment: GREYBAGS_EZT_DIR (install dir, default ~/.local/share/greybags/eztools),
#              SBECMD_URL (override download URL).
#
# SBECmd is distributed by Eric Zimmerman under his own terms; this script
# only downloads it from the official site. Record the printed SHA-256 in
# your case notes.
set -euo pipefail

USE_APT=0
NET=net9
ZIP=""
while [ $# -gt 0 ]; do
    case "$1" in
        --apt) USE_APT=1 ;;
        --net9) NET=net9 ;;
        --net6) NET=net6 ;;
        --zip) ZIP="$2"; shift ;;
        -h|--help) sed -n '2,24p' "$0"; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
    shift
done

PREFIX="${GREYBAGS_EZT_DIR:-$HOME/.local/share/greybags/eztools}"
URL="${SBECMD_URL:-https://download.ericzimmermanstools.com/${NET}/SBECmd.zip}"
CHANNEL=9.0
[ "$NET" = net6 ] && CHANNEL=8.0   # net6 builds run on 8.0 with DOTNET_ROLL_FORWARD=Major

need() { command -v "$1" >/dev/null || { echo "missing '$1' (apt-get install $2)" >&2; exit 1; }; }
need curl curl
need unzip unzip
need sha256sum coreutils

# 1. .NET runtime ------------------------------------------------------------
DOTNET=""
if command -v dotnet >/dev/null; then
    DOTNET="$(command -v dotnet)"
elif [ -x "$HOME/.dotnet/dotnet" ]; then
    DOTNET="$HOME/.dotnet/dotnet"
fi
if [ -z "$DOTNET" ]; then
    if [ "$USE_APT" -eq 1 ]; then
        SUDO=""; [ "$(id -u)" -ne 0 ] && SUDO=sudo
        $SUDO apt-get update -q
        $SUDO apt-get install -y -q dotnet-runtime-8.0
        DOTNET="$(command -v dotnet)"
        [ "$NET" = net9 ] && echo "note: distro runtime is .NET 8; consider --net6 if the net9 build refuses to start" >&2
    else
        echo "Installing .NET runtime $CHANNEL to ~/.dotnet (Microsoft dotnet-install.sh) ..."
        curl -sSfL https://dot.net/v1/dotnet-install.sh -o /tmp/dotnet-install.$$.sh
        bash /tmp/dotnet-install.$$.sh --runtime dotnet --channel "$CHANNEL" --install-dir "$HOME/.dotnet" --no-path
        rm -f /tmp/dotnet-install.$$.sh
        DOTNET="$HOME/.dotnet/dotnet"
    fi
fi
echo "dotnet: $DOTNET ($("$DOTNET" --list-runtimes 2>/dev/null | head -n1 || echo unknown))"

# 2. SBECmd ------------------------------------------------------------------
mkdir -p "$PREFIX/SBECmd"
if [ -z "$ZIP" ]; then
    ZIP="$PREFIX/SBECmd.zip"
    echo "Downloading $URL ..."
    curl -sSfL "$URL" -o "$ZIP"
fi
echo "SHA-256 $(sha256sum "$ZIP" | awk '{print $1}')  $(basename "$ZIP")"
unzip -o -q "$ZIP" -d "$PREFIX/SBECmd"
DLL="$(find "$PREFIX/SBECmd" -name SBECmd.dll -print -quit)"
[ -n "$DLL" ] || { echo "SBECmd.dll not found in the archive (is this the cross-platform .NET build?)" >&2; exit 1; }
if [ "$DLL" != "$PREFIX/SBECmd/SBECmd.dll" ]; then
    ln -sf "$DLL" "$PREFIX/SBECmd/SBECmd.dll"
fi

# 3. Wrapper -----------------------------------------------------------------
mkdir -p "$HOME/.local/bin"
cat > "$HOME/.local/bin/sbecmd" <<EOF
#!/bin/sh
export DOTNET_ROOT="$(dirname "$DOTNET")"
export DOTNET_ROLL_FORWARD="\${DOTNET_ROLL_FORWARD:-Major}"
export DOTNET_SYSTEM_GLOBALIZATION_INVARIANT="\${DOTNET_SYSTEM_GLOBALIZATION_INVARIANT:-1}"
exec "$DOTNET" "$PREFIX/SBECmd/SBECmd.dll" "\$@"
EOF
chmod +x "$HOME/.local/bin/sbecmd"

echo
echo "Installed: $PREFIX/SBECmd/SBECmd.dll"
echo "Wrapper  : $HOME/.local/bin/sbecmd  (try: sbecmd --help)"
echo "greybags finds it automatically:  greybags sbecmd run <hive-dir>"
