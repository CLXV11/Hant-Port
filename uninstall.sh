#!/data/data/com.termux/files/usr/bin/bash
# Remove HANT PORT (user data in ~/.hantport is left intact)
PREFIX="${PREFIX:-/data/data/com.termux/files/usr}"
rm -rf "$PREFIX/share/hant-port" "$PREFIX/bin/hant"
echo "HANT PORT removed. Config/reports in ~/.hantport were kept."
