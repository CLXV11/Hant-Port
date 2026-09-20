#!/data/data/com.termux/files/usr/bin/bash
# HANT PORT installer for Termux (no root required)
set -euo pipefail

PREFIX="${PREFIX:-/data/data/com.termux/files/usr}"
SRC="$(cd "$(dirname "$0")" && pwd)"
DEST="$PREFIX/share/hant-port"

if ! command -v python3 >/dev/null 2>&1; then
    echo "python3 not found. Install it first:  pkg install python"
    exit 1
fi

echo "Installing HANT PORT to $DEST ..."
mkdir -p "$DEST" "$PREFIX/bin"
cp -rf "$SRC/hantport" "$DEST/"
cp -f "$SRC/hant" "$PREFIX/bin/hant"
chmod 755 "$PREFIX/bin/hant"
echo "Done. Run:  hant --help"
