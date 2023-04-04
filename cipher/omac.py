from ctracpkm import xor
from Kuznechik import Kuznechik
import math


class OMAC(object):
    def __init__(self, block_cipher, s: int):
        assert s <= block_cipher.n
        assert block_cipher.n in {64, 128}
        self.n = self.block_cipher.n
        self.block_cipher = block_cipher
        self.s = s
        B = {
            # 64: bytearray.fromhex(hex(int("0" * 59 + "11011", 2))),
            # 128: bytearray.fromhex(hex(int("0" * 120 + "10000111", 2))),
            64: int("0" * 59 + "11011", 2),
            128: int("0" * 120 + "10000111", 2),
        }
        R = int.from_bytes(self.block_cipher.Encode(bytearray(self.n)), byteorder='big')
        K1 = R << 1 if R >> (R.bit_count() - 1) == 0 else (R << 1)
