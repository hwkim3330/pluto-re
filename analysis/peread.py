"""Read bytes/strings/dwords at a VA in pluto.dll or pluto_infer.exe.
usage: peread.py dll|exe VA [n] [s|x|d|q|f|w]"""
import sys, pefile, struct
import pathlib; _R = pathlib.Path(__file__).resolve().parent.parent / 'release'
P = {'dll': str(_R / 'pluto.dll'), 'exe': str(_R / 'pluto/pluto_infer.exe')}
_pe = {}
def pe(which):
    if which not in _pe: _pe[which] = pefile.PE(P[which], fast_load=True)
    return _pe[which]
def read(which, va, n):
    p = pe(which); rva = va - p.OPTIONAL_HEADER.ImageBase
    return p.get_data(rva, n)
def cstr(which, va, wide=False):
    b = read(which, va, 512)
    if wide:
        s = b.decode('utf-16le', 'replace'); return s.split('\0')[0]
    return b.split(b'\0')[0].decode('latin1')
if __name__ == '__main__':
    w, va = sys.argv[1], int(sys.argv[2], 16)
    n = int(sys.argv[3]) if len(sys.argv) > 3 else 64
    mode = sys.argv[4] if len(sys.argv) > 4 else 's'
    if mode == 's': print(repr(cstr(w, va)))
    elif mode == 'w': print(repr(cstr(w, va, True)))
    elif mode == 'x': print(read(w, va, n).hex(' '))
    elif mode == 'd': print([hex(x) for x in struct.unpack('<%dI' % (n//4), read(w, va, n//4*4))])
    elif mode == 'q': print([hex(x) for x in struct.unpack('<%dQ' % (n//8), read(w, va, n//8*8))])
    elif mode == 'f': print(struct.unpack('<%dd' % (n//8), read(w, va, n//8*8)))
