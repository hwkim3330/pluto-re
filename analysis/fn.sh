#!/bin/bash
# usage: fn.sh FUN_xxxxx  -> print decompiled function body (declarations stripped)
f="$(dirname "$0")/../decomp/pluto_infer.exe.c"
s=$(grep -n "^// ==== $1 " $f | cut -d: -f1)
e=$(awk -v s=$s 'NR>s && /^\/\/ ==== FUN/ {print NR; exit}' $f)
sed -n "${s},$((e-1))p" $f | grep -vE '^  (undefined[0-9]*|float|int|long|longlong|ulonglong|uint|bool|char|double|ushort|byte|size_t|short|void) [^=]*;$'
