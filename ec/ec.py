from field import Zp


class WeierstrassCurve(object):
    def __init__(self, p: int, a, b, m: int):
        """Weierstrass elliptic curve as: (y**2 = x**3 + a * x + b) in Zp
        - a, b: Zp[p].Elements params of curve formula
        - p: prime number
        """
        assert p > 2
        self.F = Zp(p)
        assert isinstance(a, self.F.Element)
        assert isinstance(b, self.F.Element)
        assert self.F[4] * (a ** 3) + self.F[27] * (b ** 2) != self.F[0]
        self.a = a
        self.b = b
        self.p = p
        self.m = m
        pass

    def __call__(self, x, y):
        return WeierstrassCurve.Point(self.p, self.a, self.b, x, y)

    def __getitem__(self, x, y):
        return WeierstrassCurve.Point(self.p, self.a, self.b, x, y)

    class Point(object):
        def __init__(self, p: int, a, b, x, y):
            assert p > 2
            self.p = p
            self.F = Zp(p)
            assert isinstance(a, self.F.Element)
            assert isinstance(b, self.F.Element)
            assert isinstance(x, self.F.Element)
            assert isinstance(y, self.F.Element)
            self.a = a
            self.b = b
            self.x = x
            self.y = y
            assert self.is_valid()

        def zero(self):
            return WeierstrassCurve.Point(self.p, self.a, self.b, self.F[0], self.F[0])

        def is_zero(self):
            return self.x == self.F[0] and self.y == self.F[0]

        def is_valid(self):
            if self.is_zero():
                return True
            left = self.y ** 2
            right = (self.x ** 3) + self.a * self.x + self.b
            return left == right

        def __eq__(self, other):
            if not isinstance(other, WeierstrassCurve.Point):
                return NotImplemented
            return self.p == other.p and self.a == other.a and self.b == other.b \
                and self.x == other.x and self.y == other.y

        def __neg__(self):
            return WeierstrassCurve.Point(self.p, self.a, self.b, self.x - self.y)

        def __add__(self, other):
            p1 = self
            p2 = other
            if p1.is_zero():
                return p2
            if p2.is_zero():
                return p1
            if p1.x == p2.x and (p1.y != p2.y or p1.y == self.F[0]):
                # p1 + -p1 == 0
                return self.zero
            if p1.x == p2.x:
                # p1 + p1: lamb = (3x^2+a)/2y
                lamb = (self.F[3] * p1.x ** 2 + self.a) / (self.F[2] * p1.y)
            else:
                # lamb = (y1 - y2)/(x1-x2)
                lamb = (p1.y - p2.y) / (p1.x - p2.x)
            x = lamb * lamb - p1.x - p2.x
            y = lamb * (p1.x - x) - p1.y
            return WeierstrassCurve.Point(self.p, self.a, self.b, x, y)

        def __mul__(self, n):
            """p*n = p + p + ... + p"""
            r = self.zero()
            cur = self
            while 0 < n:
                if n & 1 == 1:
                    r += cur
                    pass
                n, cur = n >> 1, cur + cur
                pass
            return r


def main():
    # source: https://neuromancer.sk/std/nist/P-256
    p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
    F = Zp(p)
    a = F[0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc]
    b = F[0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b]
    m = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
    p256 = WeierstrassCurve(p, a, b, m)
    print(p256.F.p)
    print(p256.m)
    G = p256(F[0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296],
             F[0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5])
    # source: http://point-at-infinity.org/ecc/nisttv
    k = 2
    G_k = p256(F[0x7CF27B188D034F7E8A52380304B51AC3C08969E277F21B35A60B48FC47669978],
               F[0x07775510DB8ED040293D9AC69F7430DBBA7DADE63CE982299E04B79D227873D1])
    assert G_k == G * k
    k = 112233445566778899112233445566778899
    G_k = p256(F[0x1B7E046A076CC25E6D7FA5003F6729F665CC3241B5ADAB12B498CD32F2803264],
               F[0xBFEA79BE2B666B073DB69A2A241ADAB0738FE9D2DD28B5604EB8C8CF097C457B])
    assert G_k == G * k


if __name__ == '__main__':
    main()
