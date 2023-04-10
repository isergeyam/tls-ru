from ctracpkm import xor
from Kuznechik import Kuznechik
import math


class OMAC(object):
    def __init__(self, block_cipher, s: int):
        assert s <= block_cipher.n
        assert block_cipher.n in {64, 128}
        self.block_cipher = block_cipher
        self.n = self.block_cipher.n
        self.block_cipher = block_cipher
        self.s = s
        B = {
            64: int("11011", 2),
            128: int("10000111", 2),
        }

        def calc_K(R):
            if R >> (self.n - 1) == 0:
                return (R << 1) & int("1" * self.n, 2)
            else:
                return ((R << 1) ^ B[self.n]) & int("1" * self.n, 2)

        R = int.from_bytes(self.block_cipher.Encode(bytearray(self.n)), byteorder='big')
        k1 = calc_K(R)
        k2 = calc_K(k1)

        self.n //= 8
        self.s //= 8

        self.K1 = k1.to_bytes(self.n, byteorder='big')
        self.K2 = k2.to_bytes(self.n, byteorder='big')

    def mac(self, message: bytearray) -> bytearray:
        m = len(message)
        q = math.ceil(m / self.n)
        c = bytearray(self.n)
        for i in range(q - 1):
            p = message[self.n * i:self.n * (i + 1)]
            c = self.block_cipher.Encode(xor(c, p))
        p = message[self.n * (q - 1):]
        k = self.K1 if len(p) == self.n else self.K2
        if len(p) < self.n:
            p += (1 << (8 * (self.n - len(p) - 1))).to_bytes(self.n - len(p), byteorder='big')
        return self.block_cipher.Encode(xor(p, xor(c, k)))[:self.s]


if __name__ == "__main__":
    K = bytearray.fromhex("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")
    P = bytearray.fromhex("""
    1122334455667700ffeeddccbbaa9988
    00112233445566778899aabbcceeff0a 
    112233445566778899aabbcceeff0a00
    2233445566778899aabbcceeff0a0011
    """)
    kuz = Kuznechik(K)
    s = 64
    omac = OMAC(kuz, s)
    assert omac.K1 == bytearray.fromhex("297d82bc4d39e3ca0de0573298151dc7")
    assert omac.K2 == bytearray.fromhex("52fb05789a73c7941bc0ae65302a3b8e")
    assert omac.mac(P) == bytearray.fromhex("336f4d296059fbe3")
