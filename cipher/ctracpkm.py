from Kuznechik import Kuznechik
import math


def xor(a: bytearray, b: bytearray):
    assert len(a) == len(b)
    result = bytearray(a)
    for i, b in enumerate(b):
        result[i] ^= b
    return result


class CtrAcpkm(object):
    def __init__(self, block_cipher, N: int, s: int):
        assert N % block_cipher.n == 0
        assert block_cipher.n % s == 0
        self.block_cipher = block_cipher
        self.N = N // 8
        self.s = s // 8
        self.n = block_cipher.n // 8

    def encode(self, IV: bytearray, message: bytearray):
        assert len(IV) == self.n // 2
        m = len(message)
        l = math.ceil(m / self.N)
        q = math.ceil(m / self.s)
        Ks = [0] * l
        Ks[0] = self.block_cipher
        for i in range(1, l):
            Ks[i] = type(self.block_cipher)(self._acpkm(Ks[i - 1]))
        ctr = int.from_bytes(IV + bytearray(self.n // 2), byteorder='big')
        C = bytearray()
        for i in range(q):
            p = message[self.s * i:self.s * (i + 1)]
            j = math.ceil((i + 1) * self.s / self.N) - 1
            ctr_bytes = bytearray(ctr.to_bytes(self.n, byteorder='big'))
            # print(f"k: {Ks[j].K.hex()}")
            # print(f"ctr: {ctr_bytes.hex()}")
            gamma = Ks[j].Encode(ctr_bytes)[:len(p)]
            # print(f"gamma: {gamma.hex()}")
            # print(f"p: {p.hex()}")
            c = xor(p, gamma)
            # print(f"c: {c.hex()}")
            C += c
            ctr += 1
        return C

    def _acpkm(self, K):
        k = len(K.K)
        assert k % self.n == 0
        D = bytearray.fromhex('808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9F')
        K1 = bytearray(0)
        for j in range(k // self.n):
            K1 += K.Encode(D[j * self.n:(j + 1) * self.n])
        return K1


if __name__ == "__main__":
    K = bytearray.fromhex(
        "88 99 AA BB CC DD EE FF 00 11 22 33 44 55 66 77 FE DC BA 98 76 54 32 10 01 23 45 67 89 AB CD EF")
    IV = bytearray.fromhex('12 34 56 78 90 AB CE F0')
    M = bytearray.fromhex("""
    11 22 33 44 55 66 77 00 FF EE DD CC BB AA 99 88 
    00 11 22 33 44 55 66 77 88 99 AA BB CC EE FF 0A 
    11 22 33 44 55 66 77 88 99 AA BB CC EE FF 0A 00 
    22 33 44 55 66 77 88 99 AA BB CC EE FF 0A 00 11 
    33 44 55 66 77 88 99 AA BB CC EE FF 0A 00 11 22 
    44 55 66 77 88 99 AA BB CC EE FF 0A 00 11 22 33 
    55 66 77 88 99 AA BB CC EE FF 0A 00 11 22 33 44
    """)
    kuz = Kuznechik(K)
    ctr = CtrAcpkm(kuz, 256, 128)
    result = ctr.encode(IV, M)
    expected = bytearray.fromhex("""
    F1 95 D8 BE C1 0E D1 DB D5 7B 5F A2 40 BD A1 B8 
    85 EE E7 33 F6 A1 3E 5D F3 3C E4 B3 3C 45 DE E4 
    4B CE EB 8F 64 6F 4C 55 00 17 06 27 5E 85 E8 00 
    58 7C 4D F5 68 D0 94 39 3E 48 34 AF D0 80 50 46 
    CF 30 F5 76 86 AE EC E1 1C FC 6C 31 6B 8A 89 6E 
    DF FD 07 EC 81 36 36 46 0C 4F 3B 74 34 23 16 3E 
    64 09 A9 C2 82 FA C8 D4 69 D2 21 E7 FB D6 DE 5D
    """)
    assert result == expected
