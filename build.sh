#!/usr/bin/env sh
# The one documented build command. Produces dist/histleak.pyz, a
# self-contained zipapp runnable as `./dist/histleak.pyz scan <path>` or
# `python3 dist/histleak.pyz scan <path>` on any machine with Python 3.10+.
#
# Not just `python3 -m zipapp`: that stamps the current wall-clock time into
# each zip entry, so two builds a minute apart produce different bytes. This
# writes entries by hand through zipfile with a fixed timestamp, so the
# build is reproducible -- run it twice and diff the hashes yourself:
#
#   ./build.sh && sha256sum dist/histleak.pyz > /tmp/h1
#   ./build.sh && sha256sum dist/histleak.pyz > /tmp/h2
#   diff /tmp/h1 /tmp/h2   # empty output means byte-identical
set -eu

mkdir -p dist
python3 build_reproducible.py
chmod +x dist/histleak.pyz
sha256sum dist/histleak.pyz 2>/dev/null || shasum -a 256 dist/histleak.pyz
