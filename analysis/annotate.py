"""Annotate Ghidra C output of pluto.dll with BW memory names and BWAPI vtable slots."""
import re, json, sys, pathlib
sys.path.insert(0, str(pathlib.Path(__file__).parent))
import bwmem
VT = json.load(open(pathlib.Path(__file__).parent / "bwapi_vtables.json"))
GAME_GLOBALS = {"DAT_63ff1034"}  # BWAPI::BroodwarPtr copy set in gameInit

HEX = re.compile(r"0x([4-6][0-9a-f]{5})\b")
GAMECALL = re.compile(r"\*(DAT_63ff1034)\s*\+\s*(0x[0-9a-f]+)\)")
VCALL = re.compile(r"\(\*\*\(code \*\*\)\(\*?\(?\w[^()]*?\+\s*(0x[0-9a-f]+)\)\)")

def note(line):
    notes = []
    for m in GAMECALL.finditer(line):
        notes.append("Game::" + VT["Game"].get(m.group(2), "?"))
    if not notes:
        for m in VCALL.finditer(line):
            off = m.group(1)
            c = [f"{k}::{VT[k][off]}" for k in ("Unit", "Player") if off in VT[k]]
            if c: notes.append("vcall " + " | ".join(c))
    for m in HEX.finditer(line):
        n = bwmem.name(int(m.group(1), 16))
        if n: notes.append(f"0x{m.group(1)}={n}")
    return line.rstrip("\n") + ("  /* " + "; ".join(dict.fromkeys(notes)) + " */" if notes else "")

if __name__ == "__main__":
    src, dst = sys.argv[1:3]
    with open(src) as f, open(dst, "w") as g:
        for line in f: g.write(note(line) + "\n")
