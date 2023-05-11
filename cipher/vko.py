import binascii

from ec import *
from Streebog import StreebogHasher




class VKO:
    def __init__(self, curve, mode):
        self.curve = curve
        self.hasher = StreebogHasher(mode)

    def digest(self, x, Q, UKM=1):
        print("point VKO", Q)
        point = Q * ((self.curve.m // self.curve.q * UKM * x) % self.curve.q)
        l = point.get_x() % self.curve.p
        r = point.get_y() % self.curve.p

        print("UKM vko", binascii.hexlify(bytearray(UKM.to_bytes(32, 'big'))))

        print("x vko", binascii.hexlify(bytearray(x.to_bytes(64, 'big'))))

        print(point)

        k = bytearray(l.to_bytes(64, 'little') + r.to_bytes(64, 'little'))



        return self.hasher << k >> 0
