#!/bin/sh
# Rebuild the CET test fixtures. Requires a gcc with -fcf-protection support.
set -e
cd "$(dirname "$0")"
gcc -fcf-protection=full -O1 -static            cet_probe.c -o cet_probe
gcc -fcf-protection=none -O1 -static            nocet.c     -o nocet
# spike: exact COP/pivot/shift gadget shapes (endbr; call rax; jmp rbx, etc.)
gcc -fcf-protection=full -O0 -static -no-pie     spike.c     -o spike
echo "built cet_probe (IBT+SHSTK), nocet (no note), spike (JOP gadget shapes)"
