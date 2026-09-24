import struct, peread
for race, va, n in (('Zerg',0x63fdd8a0,0x1a4),('Terran',0x63fdda60,0x1cc),('Protoss',0x63fddc40,0x1b8)):
    b = peread.read('dll', va, n)
    print('==', race, hex(va), n//20, 'entries')
    for i in range(n//20):
        m, a, c, d, p = struct.unpack_from('<IfffI', b, i*20)
        print('  0x%08x  vsZ=%.3f vsT=%.3f vsP=%.3f  %s' % (m, a, c, d, peread.cstr('dll', p)))
