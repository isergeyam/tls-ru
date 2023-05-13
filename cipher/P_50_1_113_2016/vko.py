from Streebog import StreebogHasher


# VKO_GOSTR3410_2012_256
# VKO_GOSTR3410_2012_512

class VKO:
    def __init__(self, curve, mode):
        self.curve = curve
        self.hasher = StreebogHasher(mode)

    def digest(self, x, Q, UKM=1):
        point = Q * (self.curve.m // self.curve.q * UKM * x)
        l = point.get_x()
        r = point.get_y()
        return self.hasher << l.to_bytes(self.curve.n, 'little') << r.to_bytes(self.curve.n, 'little') >> 0
