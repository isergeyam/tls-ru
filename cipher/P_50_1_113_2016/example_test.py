import binascii
import unittest

from KDF256 import KDF256
from hmacGOST import HMAC
from prf import PRF
from vko import VKO
from kdf_tree256 import KDFTree256

from ec.curve_params import id_tc26_gost_3410_12_512_paramSetA

from tools.formating import byte_from_hex, int_from_hex_little, int_from_hex_big


class TestExample(unittest.TestCase):

    def test_hmac256(self):
        k = byte_from_hex("""
        00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
        10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f
        """)
        hmac = HMAC(k, 256)

        t = byte_from_hex("01 26 bd b8 78 00 af 21 43 41 45 65 63 78 01 00")

        expected = byte_from_hex("""
        a1 aa 5f 7d e4 02 d7 b3 d3 23 f2 99 1c 8d 45 34
        01 31 37 01 0a 83 75 4f d0 af 6d 7c d4 92 2e d9
        """)

        res = hmac.digest(t)
        assert res == expected

    def test_hmac512(self):
        k = byte_from_hex("""
        00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
        10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f
        """)
        hmac = HMAC(k, 512)

        t = byte_from_hex("01 26 bd b8 78 00 af 21 43 41 45 65 63 78 01 00")

        expected = byte_from_hex("""
        a5 9b ab 22 ec ae 19 c6 5f bd e6 e5 f4 e9 f5 d8
        54 9d 31 f0 37 f9 df 9b 90 55 00 e1 71 92 3a 77
        3d 5f 15 30 f2 ed 7e 96 4c b2 ee dc 29 e9 ad 2f
        3a fe 93 b2 81 4f 79 f5 00 0f fc 03 66 c2 51 e6
        """)

        res = hmac.digest(t)
        assert res == expected

    def test_PRF_256(self):
        k = byte_from_hex("""
        00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
        10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f
        """)

        seed = byte_from_hex("""
        18 47 1d 62 2d c6 55 c4 d2 d2 26 96 91 ca 4a 56
        0b 50 ab a6 63 55 3a f2 41 f1 ad a8 82 c9 f2 9a
        """)

        label = byte_from_hex("11 22 33 44 55")

        prf = PRF(key=k, mode=256)

        res = prf.digest(label, seed, 512)

        expected = byte_from_hex("""
        ff 09 66 4a 44 74 58 65 94 4f 83 9e bb 48 96 5f
        15 44 ff 1c c8 e8 f1 6f 24 7e e5 f8 a9 eb e9 7f
        c4 e3 c7 90 0e 46 ca d3 db 6a 01 64 30 63 04 0e
        c6 7f c0 fd 5c d9 f9 04 65 23 52 37 bd ff 2c 02
        """)

        assert res == expected

    def test_PRF_512(self):
        k = byte_from_hex("""
        00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
        10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f
        """)

        seed = byte_from_hex("""
        18 47 1d 62 2d c6 55 c4 d2 d2 26 96 91 ca 4a 56
        0b 50 ab a6 63 55 3a f2 41 f1 ad a8 82 c9 f2 9a
        """)

        label = byte_from_hex("11 22 33 44 55")

        prf = PRF(key=k, mode=512)

        res = prf.digest(label, seed, 1024)

        expected = byte_from_hex("""
        f3 51 87 a3 dc 96 55 11 3a 0e 84 d0 6f d7 52 6c
        5f c1 fb de c1 a0 e4 67 3d d6 d7 9d 0b 92 0e 65
        ad 1b c4 7b b0 83 b3 85 1c b7 cd 8e 7e 6a 91 1a
        62 6c f0 2b 29 e9 e4 a5 8e d7 66 a4 49 a7 29 6d
        e6 1a 7a 26 c4 d1 ca ee cf d8 0c ca 65 c7 1f 0f
        88 c1 f8 22 c0 e8 c0 ad 94 9d 03 fe e1 39 57 9f
        72 ba 0c 3d 32 c5 f9 54 f1 cc cd 54 08 1f c7 44
        02 78 cb a1 fe 7b 7a 17 a9 86 fd ff 5b d1 5d 1f
        """)

        assert res == expected

    def test_VKO(self):
        curve = id_tc26_gost_3410_12_512_paramSetA()
        vko256 = VKO(curve, 256)
        vko512 = VKO(curve, 512)
        ukm = int_from_hex_little("""
        1d 80 60 3c 85 44 c7 27
        """)

        x = int_from_hex_little("""
        c9 90 ec d9 72 fc e8 4e c4 db 02 27 78 f5 0f ca
        c7 26 f4 67 08 38 4b 8d 45 83 04 96 2d 71 47 f8
        c2 db 41 ce f2 2c 90 b1 02 f2 96 84 04 f9 b9 be
        6d 47 c7 96 92 d8 18 26 b3 2b 8d ac a4 3c b6 67
        """)

        Kx = curve.G * x

        y = int_from_hex_little("""
        48 c8 59 f7 b6 f1 15 85 88 7c c0 5e c6 ef 13 90
        cf ea 73 9b 1a 18 c0 d4 66 22 93 ef 63 b7 9e 3b
        80 14 07 0b 44 91 85 90 b4 b9 96 ac fe a4 ed fb
        bb cc cc 8c 06 ed d8 bf 5b da 92 a5 13 92 d0 db
        """)

        Ky = curve.G * y

        lhs256 = vko256.digest(x, Ky, ukm)
        rhs256 = vko256.digest(y, Kx, ukm)
        lhs512 = vko512.digest(x, Ky, ukm)
        rhs512 = vko512.digest(y, Kx, ukm)

        expected256 = byte_from_hex("""
        c9 a9 a7 73 20 e2 cc 55 9e d7 2d ce 6f 47 e2 19
        2c ce a9 5f a6 48 67 05 82 c0 54 c0 ef 36 c2 21
        """)

        expected512 = byte_from_hex("""
        79 f0 02 a9 69 40 ce 7b de 32 59 a5 2e 01 52 97
        ad aa d8 45 97 a0 d2 05 b5 0e 3e 17 19 f9 7b fa
        7e e1 d2 66 1f a9 97 9a 5a a2 35 b5 58 a7 e6 d9
        f8 8f 98 2d d6 3f c3 5a 8e c0 dd 5e 24 2d 3b df
        """)

        assert lhs256 == expected256
        assert rhs256 == expected256

        assert lhs512 == expected512
        assert rhs512 == expected512

    def test_kdf256(self):
        k = byte_from_hex("""
                00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
                10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f
                """)

        my_label = byte_from_hex("26 bd b8 78")
        my_seed = byte_from_hex("af 21 43 41 45 65 63 78")
        kdf = KDF256(k)
        res = kdf(my_label, my_seed)
        exp = byte_from_hex("""
            a1 aa 5f 7d e4 02 d7 b3 d3 23 f2 99 1c 8d 45 34
            01 31 37 01 0a 83 75 4f d0 af 6d 7c d4 92 2e d9
            """)
        self.assertEqual(res, exp)

    def test_KDFTree256(self):
        k = byte_from_hex("""
                00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
                10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f
                """)
        label = byte_from_hex("""26 bd b8 78""")

        seed = byte_from_hex("""af 21 43 41 45 65 63 78""")
        kdf_tree = KDFTree256(k, label, seed, 1)

        expected = byte_from_hex("""
        22 b6 83 78 45 c6 be f6 5e a7 16 72 b2 65 83 10
        86 d3 c7 6a eb e6 da e9 1c ad 51 d8 3f 79 d1 6b
        07 4c 93 30 59 9d 7f 8d 71 2f ca 54 39 2f 4d dd
        e9 37 51 20 6b 35 84 c8 f4 3f 9e 6d c5 15 31 f9
        """)

        res = kdf_tree(512)
        assert res == expected


if __name__ == '__main__':
    unittest.main()
