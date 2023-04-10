import unittest
import time
from TLSTree import newTLSTreeKuznechik
from KDF256 import KDF256
import binascii


class TestTLSTree(unittest.TestCase):

    def test_kdf256(self):
        my_key = bytearray.fromhex("""
        00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
        10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f
        """)

        my_label = bytearray.fromhex("26 bd b8 78")
        my_seed = bytearray.fromhex("af 21 43 41 45 65 63 78")
        kdf = KDF256(my_key)
        res = kdf(my_label, my_seed)
        exp = bytearray.fromhex("""
            a1 aa 5f 7d e4 02 d7 b3 d3 23 f2 99 1c 8d 45 34
            01 31 37 01 0a 83 75 4f d0 af 6d 7c d4 92 2e d9
            """)
        self.assertEqual(res, exp)

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


if __name__ == '__main__':
    unittest.main()
