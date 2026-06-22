#!/bin/sh
# Build the CET test fixtures locally (for debugging only). The test suite builds
# these at runtime into a temp dir via tests/test_cet.py, so the binaries are not
# committed -- they are .gitignored here. Requires a gcc with -fcf-protection.
set -e
cd "$(dirname "$0")"
gcc -fcf-protection=full -O1 -no-pie cet_probe.c -o cet_probe
gcc -fcf-protection=none -O1 -no-pie nocet.c     -o nocet
echo "built cet_probe (IBT+SHSTK note) and nocet (no note)"
