from cipher.Kuznechik import Kuznechik
from ctracpkm import xor
import math


class Ctr(object):
    def __init__(self, block_cipher, s: int):
        self.s = s // 8
        self.block_cipher = block_cipher
        self.n = self.block_cipher.n // 8

    def encode(self, IV: bytearray, message: bytearray) -> bytearray:
        assert len(IV) == self.n // 2
        m = len(message)
        q = math.ceil(m / self.s)
        ctr = int.from_bytes(IV + bytearray(self.n // 2), byteorder='big')
        c = bytearray()
        for i in range(q):
            p = message[self.s * i:self.s * (i + 1)]
            ctr_bytes = ctr.to_bytes(self.n, byteorder='big')
            c += xor(p, self.block_cipher.Encode(ctr_bytes)[:len(p)])
            ctr += 1
        return c

    def decode(self, IV: bytearray, cipher: bytearray) -> bytearray:
        return self.encode(IV, cipher)


if __name__ == "__main__":
    K = bytearray.fromhex("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")
    P = bytearray.fromhex("""
    1122334455667700ffeeddccbbaa9988
    00112233445566778899aabbcceeff0a 
    112233445566778899aabbcceeff0a00
    2233445566778899aabbcceeff0a0011
    """)
    C = bytearray.fromhex("""
    f195d8bec10ed1dbd57b5fa240bda1b8
    85eee733f6a13e5df33ce4b33c45dee4
    a5eae88be6356ed3d5e877f13564a3a5
    cb91fab1f20cbab6d1c6d15820bdba73
    """)
    IV = bytearray.fromhex("1234567890abcef0")
    s = 128
    kuz = Kuznechik(K)
    ctr = Ctr(kuz, s)
    res = ctr.encode(IV, P)
    # print(binascii.hexlify(res))
    assert ctr.encode(IV, P) == C
    assert ctr.decode(IV, C) == P
