from ec import *
from Streebog import StreebogHasher


class VKO:
    def __init__(self, curve, mode):
        self.curve = curve
        self.hasher = StreebogHasher(mode)

    def digest(self, x, Q, UKM=1):
        point = Q * (self.curve.m // self.curve.q * UKM * x)
        l = point.x.val % self.curve.q
        r = point.y.val % self.curve.q

        k = bytearray(l.to_bytes(self.curve.n, 'little') + r.to_bytes(self.curve.n, 'little'))
        return self.hasher << k >> 0
