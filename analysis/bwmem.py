"""Map StarCraft 1.16.1 absolute addresses to names (from BWAPI 4.4.0 BW/ sources)."""
import re, bisect, pathlib, sys
SRC = pathlib.Path(__file__).resolve().parent.parent / "ref/bwapi/bwapi/BWAPI/Source/BW"
GAME_BASE = 0x57F0F0

def _load():
    syms = {}
    off = (SRC / "Offsets.h").read_text()
    for m in re.finditer(r"IS_REF\((\w+),\s*(0x[0-9A-Fa-f]+)\)", off):
        syms[int(m.group(2), 16)] = m.group(1)
    for m in re.finditer(r"(\w+)\s*=\s*\([^)]*\)\s*(0x[0-9A-Fa-f]{6,8})", off):
        syms.setdefault(int(m.group(2), 16), m.group(1))
    bg = (SRC / "BWGame.h").read_text()
    for m in re.finditer(r"OFFSET_ASSERT\((0x[0-9a-f]+),\s*(\w+)\)", bg):
        syms.setdefault(GAME_BASE + int(m.group(1), 16), "Game." + m.group(2))
    syms.setdefault(GAME_BASE, "Game.minerals")  # first field
    return syms

SYMS = _load()
KEYS = sorted(SYMS)

UNIT_TYPES = None
def _unit_type_names():
    global UNIT_TYPES
    if UNIT_TYPES is None:
        src = (SRC.parent.parent.parent / "include/BWAPI/UnitType.h").read_text()
        body = src[src.index("namespace Enum"):]
        body = body[body.index("{", body.index("enum Enum")) + 1:]
        UNIT_TYPES = []
        for m in re.finditer(r"^\s*(\w+)\s*(?:=\s*(\d+))?\s*,", body, flags=re.M):
            if m.group(2): UNIT_TYPES += ["?"] * (int(m.group(2)) - len(UNIT_TYPES))
            UNIT_TYPES.append(m.group(1))
            if m.group(1) == "MAX": break
    return UNIT_TYPES

def _unit_counts(addr):
    base = GAME_BASE + 0x3234; d = addr - base
    if not 0 <= d < 4 * 228 * 12 * 4: return None
    arr, r = divmod(d, 228 * 12 * 4)
    ut, r = divmod(r, 48)
    return "Game.unitCounts.%s[%s][p%d]" % (("all", "completed", "killed", "dead")[arr],
                                            _unit_type_names()[ut], r // 4)

def name(addr, maxdist=0x3000):
    u = _unit_counts(addr)
    if u: return u
    i = bisect.bisect_right(KEYS, addr) - 1
    if i < 0: return None
    base = KEYS[i]; d = addr - base
    if d > maxdist: return None
    return SYMS[base] + (f"+0x{d:x}" if d else "")

if __name__ == "__main__":
    for a in sys.argv[1:]: print(a, name(int(a, 16)))
