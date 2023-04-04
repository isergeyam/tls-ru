import math


class CtrAcpkm(object):
    def __init__(self, block_cipher, N, s):
        assert N % block_cipher.n == 0
        assert block_cipher.n % s == 0
        self.block_cipher = block_cipher
        self.N = N
        self.s = s
        self.n = block_cipher.n

    def encrypt(self, K, IV, message):
        assert len(IV) == self.n // 2
        m = len(message)
        l = math.ceil(m / self.N)
        q = math.ceil(m / self.s)
        C = ""
        Ks = [0] * l
        Ks[0] = K
        for i in range(1, l):
            Ks[i] = self._acpkm(Ks[i - 1])
        ctr = int(IV + "0" * (self.n // 2), 2)
        for i in range(q):
            p = message[self.s * i:self.s * (i + 1)]
            j = math.ceil(i * self.s / self.N)
            C += self._xor(p, self.block_cipher.encrypt(Ks[j], format(ctr, 'b'))[:len(p)])
            ctr += 1
        return C

    def _xor(self, a, b):
        assert len(a) == len(b)
        return format(int(a, 2) ^ int(b, 2), 'b').zfill(len(a))

    def _acpkm(self, K):
        k = len(K)
        assert k % self.n == 0
        D = format(0x808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9F, 'b')
        K1 = ""
        for j in range(k / self.n):
            K1 += self.block_cipher.encrypt(K, D[j * self.n:(j + 1) * self.n])
        return K1
