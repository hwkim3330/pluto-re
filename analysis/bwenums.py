"""Name tables for BW unit/order/tech/upgrade ids, parsed from the BWAPI 4.4.0 headers."""
import re, pathlib
INC = pathlib.Path(__file__).resolve().parent.parent / "ref/bwapi/bwapi/include/BWAPI"
def _enum(fname):
    src = (INC / fname).read_text()
    body = src[src.index("enum Enum"):]
    body = body[body.index("{") + 1:body.index("};")]
    body = re.sub(r"//.*", "", body)
    out, cur = {}, 0
    for m in re.finditer(r"(\w+)\s*(?:=\s*(\d+))?\s*,", body):
        if m.group(2): cur = int(m.group(2))
        out[cur] = m.group(1); cur += 1
    return out
UNIT = _enum("UnitType.h"); ORDER = _enum("Order.h"); TECH = _enum("TechType.h"); UPG = _enum("UpgradeType.h")
if __name__ == "__main__":
    import sys
    t = {"unit": UNIT, "order": ORDER, "tech": TECH, "upg": UPG}[sys.argv[1]]
    for a in sys.argv[2:]: print(a, t.get(int(a, 0)))
