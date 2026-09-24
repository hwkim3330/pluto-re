"""Read constants/tables from release/pluto.dll by virtual address.
usage: dllread.py f32|i32|u8|str ADDR [count]"""
import pefile, struct, sys, pathlib
PE = pefile.PE(str(pathlib.Path(__file__).resolve().parent.parent / "release/pluto.dll"))
BASE = PE.OPTIONAL_HEADER.ImageBase
def raw(va, n):
    return PE.get_data(va - BASE, n)
def f32(va, n=1): return list(struct.unpack("<%df" % n, raw(va, 4*n)))
def f64(va, n=1): return list(struct.unpack("<%dd" % n, raw(va, 8*n)))
def i32(va, n=1): return list(struct.unpack("<%di" % n, raw(va, 4*n)))
def u8(va, n=1): return list(raw(va, n))
def cstr(va): d = raw(va, 256); return d[:d.index(b"\0")].decode("latin1")
if __name__ == "__main__":
    k, a = sys.argv[1], int(sys.argv[2], 16); n = int(sys.argv[3]) if len(sys.argv) > 3 else 1
    print({"f32": f32, "f64": f64, "i32": i32, "u8": u8}.get(k, lambda a, n: cstr(a))(a, n))
