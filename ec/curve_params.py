from tools.utils import *
import binascii

params = [["id-tc26-gost-3410-2012-256-paramSetB", "[1.2.643.7.1.2.1.1.2]", 0],
          ['id-tc26-gost-3410-2012-256-paramSetC', '[1.2.643.7.1.2.1.1.3]', 0],
          ['id-tc26-gost-3410-2012-256-paramSetD', '[1.2.643.7.1.2.1.1.4]', 0],
          ['id-tc26-gost-3410-12-512-paramSetA', '[1.2.643.7.1.2.1.2.1]', 0],
          ['id-tc26-gost-3410-12-512-paramSetB', '[1.2.643.7.1.2.1.2.2]', 0],
          ['id-tc26-gost-3410-2012-256-paramSetA', '[1.2.643.7.1.2.1.1.1]', 0],
          ['id-tc26-gost-3410-2012-512-paramSetC', '[1.2.643.7.1.2.1.2.3]', 0]
          ]

for p in params:
    p[2] = encode_OID_from_str(p[1])
    print(p[0], p[1], binascii.hexlify(p[2]) )


