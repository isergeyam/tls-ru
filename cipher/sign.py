from ec.elliptic import *
from cipher.Streebog import StreebogHasher
from random import randint


class Sign:
    def __init__(self, curve, P, mode, d, Q):
        self.p = curve.p
        self.a = curve.a
        self.b = curve.b
        self.m = curve.m
        self.q = curve.q
        self.q = curve.q
        self.P = P
        self.hasher = StreebogHasher(mode)
        self.mode = mode // 8
        self.d = d
        self.Q = Q

    def sign(self, message: bytearray):
        h = self.hasher << message >> 0
        e = int.from_bytes(h, 'big') % self.q
        e = 1 if e == 0 else e
        while True:
            k = randint(1, self.q - 1)
            C = self.P * k
            r = C.x.val
            if r != 0:
                s = (k * e + self.d * r) % self.q
                if s != 0:
                    break
        r = r.to_bytes(self.mode, 'big')
        s = s.to_bytes(self.mode, 'big')

        return bytearray(r + s)

    def verify(self, zeta: bytearray, message: bytearray):
        r = int.from_bytes(zeta[0: len(zeta) // 2], 'big')
        s = int.from_bytes(zeta[len(zeta) // 2:], 'big')
        if r <= 0 or r >= self.q:
            return 0
        if s <= 0 or s >= self.q:
            return 0
        h = self.hasher << message >> 0
        e = int.from_bytes(h, 'big') % self.q
        e = 1 if e == 0 else e

        F = Zp(self.q)
        e = F[e]
        v = e ** (-1)

        z1 = s * v.val % self.q
        z2 = -r * v.val % self.q
        C = self.P * z1 + self.Q * z2
        R = C.x.val
        if R == r:
            return 1
        else:
            return 0


