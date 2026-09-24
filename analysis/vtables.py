"""Build MSVC vtable layouts for BWAPI 4.4.0 interfaces from the headers.

MSVC rules used: a class's virtuals are laid out in declaration order, except
that overloads of one name are grouped at the first declaration's position,
in reverse declaration order. One slot for the virtual destructor.
"""
import re, sys, json, pathlib
INC = pathlib.Path(__file__).resolve().parent.parent / "ref/bwapi/bwapi/include/BWAPI"

def strip(src):
    src = re.sub(r"//.*", "", src)
    return re.sub(r"/\*.*?\*/", "", src, flags=re.S)

def class_body(src, name):
    m = re.search(r"\bclass\s+(?:BWAPI_EXPORT\s+)?%s\b[^;{]*\{" % name, src)
    i = m.end(); depth = 1
    while depth:
        depth += {"{": 1, "}": -1}.get(src[i], 0); i += 1
    return src[m.end():i - 1]

def virtuals(body):
    # drop inline bodies of non-virtual helpers so their braces don't confuse us
    out = []
    for m in re.finditer(r"\bvirtual\b(.*?)(?:=\s*0\s*;|;|\{)", body, flags=re.S):
        decl = " ".join(m.group(1).split())
        nm = re.search(r"(~?\w+|operator\S+)\s*\(", decl)
        out.append((nm.group(1), decl))
    return out

def msvc_layout(vs):
    order, groups = [], {}
    for n, d in vs:
        if n not in groups: groups[n] = []; order.append(n)
        groups[n].append(d)
    slots = []
    for n in order:
        for d in reversed(groups[n]): slots.append((n, d))
    return slots

def layout(header, cls, base=None):
    body = class_body(strip((INC / header).read_text()), cls)
    s = msvc_layout(virtuals(body))
    if base:  # derived destructor overrides the base's slot
        s = [x for x in s if not x[0].startswith("~")]
        return layout(*base) + s
    return s

TABLES = {
    "Game": layout("Game.h", "Game"),
    "Unit": layout("Unit.h", "UnitInterface", ("Interface.h", "Interface")),
    "Player": layout("Player.h", "PlayerInterface", ("Interface.h", "Interface")),
    "Force": layout("Force.h", "ForceInterface", ("Interface.h", "Interface")),
    "Region": layout("Region.h", "RegionInterface", ("Interface.h", "Interface")),
    "Bullet": layout("Bullet.h", "BulletInterface", ("Interface.h", "Interface")),
    "AIModule": layout("AIModule.h", "AIModule"),
}
if __name__ == "__main__":
    out = {}
    for k, s in TABLES.items():
        out[k] = {hex(i * 4): d for i, (n, d) in enumerate(s)}
    json.dump(out, open(pathlib.Path(__file__).parent / "bwapi_vtables.json", "w"), indent=1)
    for k in sys.argv[1:]:
        for off, d in out[k].items(): print(off, d)
