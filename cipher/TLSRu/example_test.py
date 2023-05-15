import binascii
import unittest
from TLSTree import newTLSTreeKuznechik

from ec.curve_params import id_tc26_gost_3410_2012_512_paramSetC, \
    id_tc26_gost_3410_12_512_paramSetA, id_tc26_gost_3410_2012_256_paramSetB
from tools.formating import byte_from_hex, int_from_hex_big

from KEG import KEG

from cipher.Streebog import StreebogHasher


class TestTLSTree(unittest.TestCase):

    def test_tlstree(self):
        my_key = bytearray.fromhex("""
        FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
        FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
        """)
        tree = newTLSTreeKuznechik(my_key)
        indexs = [0, 63, 64, 524287, 524288, 4294967295, 4294967296]
        results_hex = [
            """50 76 42 D9 58 C5 20 C6 D7 EE F5 CA 8A 53 16 D4 F3 4B 85 5D 2D D4 BC BF 4E 5B F0 FF 64 1A 19 FF""",
            """50 76 42 D9 58 C5 20 C6 D7 EE F5 CA 8A 53 16 D4 F3 4B 85 5D 2D D4 BC BF 4E 5B F0 FF 64 1A 19 FF""",
            """C1 9B 63 9F 4B EA 78 8C 1C 59 B4 C8 87 DB 5B 07 C1 91 19 10 18 68 DA B8 9A 8D 93 61 B2 F0 10 F3""",
            """92 30 3E B5 61 56 88 54 E3 3E 4F E0 97 A9 95 99 17 9F 5B 90 94 AE 34 79 E6 1C 43 69 3A 3F 0A 06""",
            """E8 55 A0 E2 CB DD 68 C1 13 7C EF 3E 80 1E 0B FF 68 62 8C 36 43 68 27 6D 0C B8 7E B5 6E 94 EF 42""",
            """93 D3 CA E9 5A 55 B7 1A A3 B9 A7 DD F9 9A 6A AC 3F DA 17 2A 79 60 58 04 A9 C9 FC 6E 84 8A F1 AA""",
            """7F FB 1A D7 E5 7B 70 BE 10 96 31 D2 71 92 98 B9 7D EE 3B 00 8D 86 F8 3D AA F6 2A 4E A5 B7 AA FD"""

        ]
        result_bytes = [bytearray.fromhex(results_hex[i]) for i in range(7)]
        for j in range(7):
            res = tree(indexs[j])
            self.assertEqual(res, result_bytes[j])

    def test_KEG_1_3_1(self):
        curve = id_tc26_gost_3410_2012_256_paramSetB()
        ks = int_from_hex_big("""
        5F308355DFD6A8ACAEE0837B100A3B1F
        6D63FB29B78EF27D3967757F0527144C
        """)

        Qs = curve.G * ks

        keph = int_from_hex_big("""
        A5C77C7482373DE16CE4A6F73CCE7F78
        471493FF2C0709B8B706C9E8A25E6C1E
        """)

        Qeph = curve.G * keph

        H = byte_from_hex("""
        C3 EF 04 28 D4 B7 A1 F4 C5 02 5F 2E 65 DD 2B 2E
        A5 83 AE EF DB 67 C7 F4 21 4A 6A 29 8E 99 E3 25
        """)

        keg = KEG(curve)
        lhs = keg(keph, Qs, H)
        rhs = keg(ks, Qeph, H)

        Q = curve.G * (keph * ks)

        hasher = StreebogHasher(256)

        expected = byte_from_hex("""
        2D 8B A8 C8 4C B2 32 FF 41 F1 0C 3A D9 24 13 42
        23 25 4F 71 E5 69 6D 3D 29 C3 E4 C9 DA A6 B2 93
        84 9E B6 34 0B FF AE 69 28 A3 C3 E4 FF 92 EC CB
        1E 8F 0C F7 A1 88 36 8E 6B 74 8E 52 EA 37 8B 0C
        """)

        assert expected == lhs and expected == rhs

    def test_KEG_1(self):
        curve = id_tc26_gost_3410_12_512_paramSetA()
        ks = int_from_hex_big("""
        5F1E83AFA2C4CB2C5633C51380E84E37
        4B013EE7C238330709080CE914B442D4
        34EB016D23FB63FEDC18B62D9DA93D26
        B3B9CE6F663B383303BD5930ED41608B
        """)

        Qs = curve.G * ks

        keph = int_from_hex_big("""
        C96486B1A3732389A162F5AD0145D537
        43C9AC27D42ACF1091CE7EF67E6C3CCA
        0F6C879B2DA3C1607648BAEB96471BD2
        078DF5CAAA4FA83ECC0FFD6D3C8E5D56
        """)

        Qeph = curve.G * keph

        H = byte_from_hex("""
        FB F3 9D 10 E8 00 AF 70 E7 AA 22 C1 10 DA 94 A9
        9A 58 98 D8 45 27 C7 CB DE C1 1E 53 39 90 6A 1A
        """)

        keg = KEG(curve)
        lhs = keg(keph, Qs, H)
        rhs = keg(ks, Qeph, H)
        print(binascii.hexlify(keph.to_bytes(64, 'big')))
        print(Qs)
        print(Qeph)
        print(binascii.hexlify(lhs))
        print(binascii.hexlify(rhs))

        print("done")

    def test_KEG_1_3_2(self):
        curve = id_tc26_gost_3410_2012_512_paramSetC()

        ks = int_from_hex_big("""
        12FD7A70067479A0F66C59F9A25534AD
        FBC7ABFD3CC72D79806F8B402601644B
        3005ED365A2D8989A8CCAE640D5FC08D
        D27DFBBFE137CF528E1AC6D445192E01
        """)

        Qs = curve.G * ks

        keph = int_from_hex_big("""
        150ACD11B66DD695AD18418FA7A2DC63
        6B7E29DCA24536AABC826EE3175BB1FA
        DC3AA0D01D3092E120B0FCF7EB872F4B
        7E26EA17849D689222A48CF95A6E4831
        """)

        Qeph = curve.G * keph

        H = byte_from_hex("""
        C3 EF 04 28 D4 B7 A1 F4 C5 02 5F 2E 65 DD 2B 2E
        A5 83 AE EF DB 67 C7 F4 21 4A 6A 29 8E 99 E3 25
        """)

        keg = KEG(curve)
        lhs = keg(keph, Qs, H)
        rhs = keg(ks, Qeph, H)

        expected = byte_from_hex("""
        7D AC 56 E4 8A 4D C1 70 FA A8 FC BA E2 0D B8 45
        45 0C CC C4 C6 32 8B DC 8D 01 15 7C EF A2 A5 F1
        1F 1C BA D8 86 61 66 F0 1F FA AB 01 52 E2 4B F4
        60 9D 5F 46 A5 C8 99 C7 87 90 0D 08 B9 FC AD 24
        """)

        assert expected == lhs and expected == rhs


if __name__ == '__main__':
    unittest.main()
