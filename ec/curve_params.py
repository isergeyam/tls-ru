from tools.utils import *
import binascii
from ec.field import Zp
from ec.elliptic import WeierstrassCurve
from ec.elliptic import TwistedEdwardsCurve

params = [["id-tc26-gost-3410-2012-256-paramSetB", "[1.2.643.7.1.2.1.1.2]", 0],
          ['id-tc26-gost-3410-2012-256-paramSetC', '[1.2.643.7.1.2.1.1.3]', 0],
          ['id-tc26-gost-3410-2012-256-paramSetD', '[1.2.643.7.1.2.1.1.4]', 0],
          ['id-tc26-gost-3410-12-512-paramSetA', '[1.2.643.7.1.2.1.2.1]', 0],
          ['id-tc26-gost-3410-12-512-paramSetB', '[1.2.643.7.1.2.1.2.2]', 0],
          ['id-tc26-gost-3410-2012-256-paramSetA', '[1.2.643.7.1.2.1.1.1]', 0],
          ['id-tc26-gost-3410-2012-512-paramSetC', '[1.2.643.7.1.2.1.2.3]', 0],
          ['id-GostR3410-2001-CryptoPro-A-ParamSet', '[1.2.643.2.2.36.0]', 0],
          ['id-GostR3410-2001-CryptoPro-C-ParamSet', '[1.2.643.2.2.35.3]', 0]
          ]

curve_params_to_ec = dict()

for p in params:
    p[2] = int.from_bytes(encode_OID_from_str(p[1]), 'big')


def construct_weierstrass(p, a, b, m, q, x, y):
    F = Zp(p)
    a = F[a]
    b = F[b]
    x = F[x]
    y = F[y]
    ec = WeierstrassCurve(p, a, b, m, q)
    ec.G = ec(x, y)
    return ec


def id_tc26_gost_3410_2012_256_paramSetB():
    p = int.from_bytes(bytes.fromhex("""
    00 FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
    FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FD
    97
    """), 'big')
    a = int.from_bytes(bytes.fromhex("""
    00 FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
    FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FD
    94
    """), 'big')
    b = 0xA6
    m = int.from_bytes(bytes.fromhex("""
    00 FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
    FF 6C 61 10 70 99 5A D1 00 45 84 1B 09 B7 61 B8
    93
    """), 'big')
    q = int.from_bytes(bytes.fromhex("""
    00 FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
    FF 6C 61 10 70 99 5A D1 00 45 84 1B 09 B7 61 B8
    93
    """), 'big')
    x = 0x01
    y = int.from_bytes(bytes.fromhex("""
    00 8D 91 E4 71 E0 98 9C DA 27 DF 50 5A 45 3F 2B
    76 35 29 4F 2D DF 23 E3 B1 22 AC C9 9C 9E 9F 1E
    14
    """), 'big')
    return construct_weierstrass(p, a, b, m, q, x, y)


def id_tc26_gost_3410_2012_256_paramSetC():
    p = int.from_bytes(bytes.fromhex("""
    00 80 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 0C
    99
    """), 'big')
    a = int.from_bytes(bytes.fromhex("""
    00 80 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 0C
    96
    """), 'big')
    b = int.from_bytes(bytes.fromhex("""
    3E 1A F4 19 A2 69 A5 F8 66 A7 D3 C2 5C 3D F8 0A
    E9 79 25 93 73 FF 2B 18 2F 49 D4 CE 7E 1B BC 8B
    """), 'big')
    m = int.from_bytes(bytes.fromhex("""
    00 80 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    01 5F 70 0C FF F1 A6 24 E5 E4 97 16 1B CC 8A 19
    8F
    """), 'big')
    q = int.from_bytes(bytes.fromhex("""
    00 80 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    01 5F 70 0C FF F1 A6 24 E5 E4 97 16 1B CC 8A 19
    8F
    """), 'big')
    x = 0x01
    y = int.from_bytes(bytes.fromhex("""
    3F A8 12 43 59 F9 66 80 B8 3D 1C 3E B2 C0 70 E5
    C5 45 C9 85 8D 03 EC FB 74 4B F8 D7 17 71 7E FC
    """), 'big')
    return construct_weierstrass(p, a, b, m, q, x, y)


def id_tc26_gost_3410_2012_256_paramSetD():
    p = int.from_bytes(bytes.fromhex("""
    00 9B 9F 60 5F 5A 85 81 07 AB 1E C8 5E 6B 41 C8
    AA CF 84 6E 86 78 90 51 D3 79 98 F7 B9 02 2D 75
    9B
    """), 'big')
    a = int.from_bytes(bytes.fromhex("""
    00 9B 9F 60 5F 5A 85 81 07 AB 1E C8 5E 6B 41 C8
    AA CF 84 6E 86 78 90 51 D3 79 98 F7 B9 02 2D 75
    98
    """), 'big')
    b = int.from_bytes(bytes.fromhex("""
    80 5A
    """), 'big')
    m = int.from_bytes(bytes.fromhex("""
    00 9B 9F 60 5F 5A 85 81 07 AB 1E C8 5E 6B 41 C8
    AA 58 2C A3 51 1E DD FB 74 F0 2F 3A 65 98 98 0B
    B9
    """), 'big')
    q = int.from_bytes(bytes.fromhex("""
    00 9B 9F 60 5F 5A 85 81 07 AB 1E C8 5E 6B 41 C8
    AA 58 2C A3 51 1E DD FB 74 F0 2F 3A 65 98 98 0B
    B9
    """), 'big')
    x = 0x00
    y = int.from_bytes(bytes.fromhex("""
    41 EC E5 57 43 71 1A 8C 3C BF 37 83 CD 08 C0 EE
    4D 4D C4 40 D4 64 1A 8F 36 6E 55 0D FD B3 BB 67
    """), 'big')
    return construct_weierstrass(p, a, b, m, q, x, y)


def id_tc26_gost_3410_12_512_paramSetA():
    p = int.from_bytes(bytes.fromhex("""
    00 FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
    FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
    FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
    FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FD
    C7
    """), 'big')
    a = int.from_bytes(bytes.fromhex("""
    00 FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
    FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
    FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
    FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FD
    C4
    """), 'big')
    b = int.from_bytes(bytes.fromhex("""
    00 E8 C2 50 5D ED FC 86 DD C1 BD 0B 2B 66 67 F1
    DA 34 B8 25 74 76 1C B0 E8 79 BD 08 1C FD 0B 62
    65 EE 3C B0 90 F3 0D 27 61 4C B4 57 40 10 DA 90
    DD 86 2E F9 D4 EB EE 47 61 50 31 90 78 5A 71 C7
    60
    """), 'big')
    m = int.from_bytes(bytes.fromhex("""
    00 FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
    FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
    FF 27 E6 95 32 F4 8D 89 11 6F F2 2B 8D 4E 05 60
    60 9B 4B 38 AB FA D2 B8 5D CA CD B1 41 1F 10 B2
    75
    """), 'big')
    q = int.from_bytes(bytes.fromhex("""
    00 FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
    FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
    FF 27 E6 95 32 F4 8D 89 11 6F F2 2B 8D 4E 05 60
    60 9B 4B 38 AB FA D2 B8 5D CA CD B1 41 1F 10 B2
    75
    """), 'big')
    x = 0x03
    y = int.from_bytes(bytes.fromhex("""
    75 03 CF E8 7A 83 6A E3 A6 1B 88 16 E2 54 50 E6
    CE 5E 1C 93 AC F1 AB C1 77 80 64 FD CB EF A9 21
    DF 16 26 BE 4F D0 36 E9 3D 75 E6 A5 0E 3A 41 E9
    80 28 FE 5F C2 35 F5 B8 89 A5 89 CB 52 15 F2 A4
    """), 'big')
    return construct_weierstrass(p, a, b, m, q, x, y)


def id_tc26_gost_3410_12_512_paramSetB():
    p = int.from_bytes(bytes.fromhex("""
    00 80 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    6F
    """), 'big')
    a = int.from_bytes(bytes.fromhex("""
    00 80 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    6C
    """), 'big')
    b = int.from_bytes(bytes.fromhex("""
    68 7D 1B 45 9D C8 41 45 7E 3E 06 CF 6F 5E 25 17
    B9 7C 7D 61 4A F1 38 BC BF 85 DC 80 6C 4B 28 9F
    3E 96 5D 2D B1 41 6D 21 7F 8B 27 6F AD 1A B6 9C
    50 F7 8B EE 1F A3 10 6E FB 8C CB C7 C5 14 01 16
    """), 'big')
    m = int.from_bytes(bytes.fromhex("""
    00 80 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    01 49 A1 EC 14 25 65 A5 45 AC FD B7 7B D9 D4 0C
    FA 8B 99 67 12 10 1B EA 0E C6 34 6C 54 37 4F 25
    BD
    """), 'big')
    q = int.from_bytes(bytes.fromhex("""
    00 80 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    01 49 A1 EC 14 25 65 A5 45 AC FD B7 7B D9 D4 0C
    FA 8B 99 67 12 10 1B EA 0E C6 34 6C 54 37 4F 25
    BD
    """), 'big')
    x = 0x02
    y = int.from_bytes(bytes.fromhex("""
    1A 8F 7E DA 38 9B 09 4C 2C 07 1E 36 47 A8 94 0F
    3C 12 3B 69 75 78 C2 13 BE 6D D9 E6 C8 EC 73 35
    DC B2 28 FD 1E DF 4A 39 15 2C BC AA F8 C0 39 88
    28 04 10 55 F9 4C EE EC 7E 21 34 07 80 FE 41 BD
    """), 'big')
    return construct_weierstrass(p, a, b, m, q, x, y)


def construct_edwards(p, a, b, e, d, m, q, x, y, u, v):
    F = Zp(p)
    a = F[a]
    b = F[b]
    e = F[e]
    d = F[d]
    x = F[x]
    y = F[y]
    u = F[u]
    v = F[v]
    ec = TwistedEdwardsCurve(p, e, d, m, q)
    ec.G = ec(u, v)
    w_ec = WeierstrassCurve(p, a, b, m, q)
    w_ec.G = w_ec(x, y)
    return ec, w_ec


def id_tc26_gost_3410_2012_256_paramSetA():
    p = int.from_bytes(bytes.fromhex("""
    00 FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
    FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FD 
    97
    """), 'big')
    a = int.from_bytes(bytes.fromhex("""
    00 C2 17 3F 15 13 98 16 73 AF 48 92 C2 30 35 A2 
    7C E2 5E 20 13 BF 95 AA 33 B2 2C 65 6F 27 7E 73
    35
    """), 'big')
    b = int.from_bytes(bytes.fromhex("""
    29 5F 9B AE 74 28 ED 9C CC 20 E7 C3 59 A9 D4 1A
    22 FC CD 91 08 E1 7B F7 BA 93 37 A6 F8 AE 95 13
    """), 'big')
    e = 0x01
    d = int.from_bytes(bytes.fromhex("""
    06 05 F6 B7 C1 83 FA 81 57 8B C3 9C FA D5 18 13
    2B 9D F6 28 97 00 9A F7 E5 22 C3 2D 6D C7 BF FB
    """), 'big')
    m = int.from_bytes(bytes.fromhex("""
    01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    00 3F 63 37 7F 21 ED 98 D7 04 56 BD 55 B0 D8 31
    9C
    """), 'big')
    q = int.from_bytes(bytes.fromhex("""
    40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    0F D8 CD DF C8 7B 66 35 C1 15 AF 55 6C 36 0C 67
    """), 'big')
    x = int.from_bytes(bytes.fromhex("""
    00 91 E3 84 43 A5 E8 2C 0D 88 09 23 42 57 12 B2
    BB 65 8B 91 96 93 2E 02 C7 8B 25 82 FE 74 2D AA
    28
    """), 'big')
    y = int.from_bytes(bytes.fromhex("""
    32 87 94 23 AB 1A 03 75 89 57 86 C4 BB 46 E9 56
    5F DE 0B 53 44 76 67 40 AF 26 8A DB 32 32 2E 5C
    """), 'big')
    u = 0x0D
    v = int.from_bytes(bytes.fromhex("""
    60 CA 1E 32 AA 47 5B 34 84 88 C3 8F AB 07 64 9C
    E7 EF 8D BE 87 F2 2E 81 F9 2B 25 92 DB A3 00 E7
    """), 'big')
    return construct_weierstrass(p, a, b, m, q, x, y)
    # return construct_edwards(p, a, b, e, d, m, q, x, y, u, v)


def id_tc26_gost_3410_2012_512_paramSetC():
    p = int.from_bytes(bytes.fromhex("""
    00 FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
    FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
    FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
    FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FD
    C7
    """), 'big')
    a = int.from_bytes(bytes.fromhex("""
    00 DC 92 03 E5 14 A7 21 87 54 85 A5 29 D2 C7 22
    FB 18 7B C8 98 0E B8 66 64 4D E4 1C 68 E1 43 06
    45 46 E8 61 C0 E2 C9 ED D9 2A DE 71 F4 6F CF 50
    FF 2A D9 7F 95 1F DA 9F 2A 2E B6 54 6F 39 68 9B
    D3
    """), 'big')
    b = int.from_bytes(bytes.fromhex("""
    00 B4 C4 EE 28 CE BC 6C 2C 8A C1 29 52 CF 37 F1
    6A C7 EF B6 A9 F6 9F 4B 57 FF DA 2E 4F 0D E5 AD
    E0 38 CB C2 FF F7 19 D2 C1 8D E0 28 4B 8B FE F3
    B5 2B 8C C7 A5 F5 BF 0A 3C 8D 23 19 A5 31 25 57
    E1
    """), 'big')
    e = 0x01
    d = int.from_bytes(bytes.fromhex("""
    00 9E 4F 5D 8C 01 7D 8D 9F 13 A5 CF 3C DF 5B FE
    4D AB 40 2D 54 19 8E 31 EB DE 28 A0 62 10 50 43
    9C A6 B3 9E 0A 51 5C 06 B3 04 E2 CE 43 E7 9E 36
    9E 91 A0 CF C2 BC 2A 22 B4 CA 30 2D BB 33 EE 75
    50
    """), 'big')
    m = int.from_bytes(bytes.fromhex("""
    00 FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
    FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
    FF 26 33 6E 91 94 1A AC 01 30 CE A7 FD 45 1D 40
    B3 23 B6 A7 9E 9D A6 84 9A 51 88 F3 BD 1F C0 8F
    B4
    """), 'big')
    q = int.from_bytes(bytes.fromhex("""
    3F FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
    FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
    C9 8C DB A4 65 06 AB 00 4C 33 A9 FF 51 47 50 2C
    C8 ED A9 E7 A7 69 A1 26 94 62 3C EF 47 F0 23 ED
    """), 'big')
    x = int.from_bytes(bytes.fromhex("""
    00 E2 E3 1E DF C2 3D E7 BD EB E2 41 CE 59 3E F5
    DE 22 95 B7 A9 CB AE F0 21 D3 85 F7 07 4C EA 04
    3A A2 72 72 A7 AE 60 2B F2 A7 B9 03 3D B9 ED 36
    10 C6 FB 85 48 7E AE 97 AA C5 BC 79 28 C1 95 01
    48
    """), 'big')
    y = int.from_bytes(bytes.fromhex("""
    00 F5 CE 40 D9 5B 5E B8 99 AB BC CF F5 91 1C B8
    57 79 39 80 4D 65 27 37 8B 8C 10 8C 3D 20 90 FF
    9B E1 8E 2D 33 E3 02 1E D2 EF 32 D8 58 22 42 3B
    63 04 F7 26 AA 85 4B AE 07 D0 39 6E 9A 9A DD C4
    0F
    """), 'big')
    u = 0x12
    v = int.from_bytes(bytes.fromhex("""
    46 9A F7 9D 1F B1 F5 E1 6B 99 59 2B 77 A0 1E 2A
    0F DF B0 D0 17 94 36 8D 9A 56 11 7F 7B 38 66 95
    22 DD 4B 65 0C F7 89 EE BF 06 8C 5D 13 97 32 F0
    90 56 22 C0 4B 2B AA E7 60 03 03 EE 73 00 1A 3D
    """), 'big')
    return construct_weierstrass(p, a, b, m, q, x, y)
    # return construct_edwards(p, a, b, e, d, m, q, x, y, u, v)


ru_curves = {params[0][2]: id_tc26_gost_3410_2012_256_paramSetB(), params[1][2]: id_tc26_gost_3410_2012_256_paramSetC(),
             params[2][2]: id_tc26_gost_3410_2012_256_paramSetD(), params[3][2]: id_tc26_gost_3410_12_512_paramSetA(),
             params[4][2]: id_tc26_gost_3410_12_512_paramSetB(),
             params[5][2]: id_tc26_gost_3410_2012_256_paramSetA(),
             params[6][2]: id_tc26_gost_3410_2012_512_paramSetC(),
             params[7][2]: id_tc26_gost_3410_2012_256_paramSetB(),
             params[8][2]: id_tc26_gost_3410_2012_256_paramSetD(),
             }


def get_curve(oid: bytearray):
    val = int.from_bytes(oid, 'big')
    return ru_curves[int.from_bytes(oid, 'big')]


if __name__ == "__main__":
    print(ru_curves)

    test = id_tc26_gost_3410_2012_256_paramSetB()
    p = test.G
    print(id_tc26_gost_3410_2012_256_paramSetB().G)
    print(id_tc26_gost_3410_2012_256_paramSetC().G)
    print(id_tc26_gost_3410_2012_256_paramSetD().G)
    print(id_tc26_gost_3410_12_512_paramSetA().G)
    print(id_tc26_gost_3410_12_512_paramSetB().G)
    print(id_tc26_gost_3410_2012_256_paramSetA().G)
    print(id_tc26_gost_3410_2012_512_paramSetC().G)
