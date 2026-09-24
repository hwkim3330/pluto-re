"""Read static data from pluto.dll by VA: rd.py <va_hex> <count> [fmt: i|I|h|H|b|B|f]"""
import sys, struct, pefile, pathlib
pe = pefile.PE(str(pathlib.Path(__file__).resolve().parent.parent / "release/pluto.dll"))
def read(va, n):
    return pe.get_data(va - pe.OPTIONAL_HEADER.ImageBase, n)
if __name__ == "__main__":
    va = int(sys.argv[1], 16); cnt = int(sys.argv[2]); fmt = sys.argv[3] if len(sys.argv) > 3 else "i"
    sz = struct.calcsize(fmt)
    vals = struct.unpack("<%d%s" % (cnt, fmt), read(va, cnt * sz))
    for i in range(0, cnt, 16):
        print(hex(va + i * sz), vals[i:i + 16])
