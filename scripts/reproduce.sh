#!/usr/bin/env bash
# Regenerate everything this repo's analysis was done on:
# release binaries, BWAPI 4.4.0 headers, Ghidra decompilation, annotation.
set -euo pipefail
cd "$(dirname "$0")/.."
TAG=${TAG:-cog2026-2578600}
GHIDRA=${GHIDRA:-$HOME/tools/ghidra_12.1.4_PUBLIC}

if [ ! -f release/pluto.dll ]; then
  gh release download "$TAG" -R tscmoo/pluto --clobber
  echo "d4e2225446f5048e131065357173952f0286586da77ebb8bddf7fc766c3844a5  pluto-$TAG.zip" | sha256sum -c
  unzip -o -q "pluto-$TAG.zip" -d release
fi
[ -d ref/bwapi ] || git clone -q --depth 1 --branch v4.4.0 https://github.com/bwapi/bwapi.git ref/bwapi

mkdir -p gproj decomp
for f in release/pluto.dll release/pluto/pluto_infer.exe; do
  b=$(basename "$f")
  [ -s "decomp/$b.c" ] && continue
  # run sequentially: parallel first runs race on creating ~/.config/ghidra
  "$GHIDRA/support/analyzeHeadless" gproj "pluto_$b" -import "$f" -overwrite \
    -scriptPath ghidra_scripts -postScript DecompileAll.java "$PWD/decomp/$b.c" > "decomp/$b.log" 2>&1
  strings -n 5 "$f" | awk 'length<300' > "decomp/$b.strings"
done

python3 analysis/vtables.py
python3 analysis/annotate.py decomp/pluto.dll.c decomp/pluto.dll.annotated.c
echo "done: decomp/"
