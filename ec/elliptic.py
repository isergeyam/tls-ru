import binascii

from ec.field import Zp
import typing as tp

import os


class WeierstrassCurve(object):
    def __init__(self, p: int, a, b, m: int, q: int):
        """Weierstrass elliptic curve as: (y**2 = x**3 + a * x + b) in Zp
        - a, b: Zp[p].Elements params of curve formula
        - p: prime number
        """
        assert p > 2
        self.n = (p.bit_length() + 7) // 8
        self.F = Zp(p)
        assert isinstance(a, self.F.Element)
        assert isinstance(b, self.F.Element)
        assert self.F[4] * (a ** 3) + self.F[27] * (b ** 2) != self.F[0]
        self.a = a
        self.b = b
        self.p = p
        self.m = m
        self.q = q
        pass

    def random(self):
        return int.from_bytes(os.urandom(512), 'big') % self.p + 1

    def __call__(self, x, y):
        return WeierstrassCurve.Point(self.p, self.a, self.b, x, y)

    def __getitem__(self, x, y):
        return WeierstrassCurve.Point(self.p, self.a, self.b, x, y)

    class Point(object):

        def __init__(self, p: tp.Union[int, bool], a, b, x, y):
            if isinstance(p, bool):
                self.zero_point = True
                return

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
            self.zero_point = False
            assert self.is_valid()

        def zero(self):
            return WeierstrassCurve.Point(True, 0, 0, 0, 0)

        def is_zero(self):
            return self.zero_point

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
                return self.zero()
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

        def __str__(self):
            return hex(self.x.val) + "\n" + hex(self.y.val)

        def get_x(self):
            return self.x

        def get_y(self):
            return self.y


class TwistedEdwardsCurve(object):
    def __init__(self, p: int, a, d, m, q: int):
        """TwistedEdwards elliptic curve as: ax**2 + y**2 = 1 + dx**2y**2 in Zp
        - a, d: Zp[p].Elements params of curve formula
        - p: prime number
        """
        assert p > 2
        self.F = Zp(p)
        assert isinstance(a, self.F.Element)
        assert isinstance(d, self.F.Element)
        self.a = a
        self.d = d
        self.p = p
        self.m = m
        self.q = q
        self.weierstrass = WeierstrassCurve(p, *self._to_weierstrass_params(), m, q)

    def random(self):
        return 2 * int.from_bytes(os.urandom(512), 'big') % self.q + 1

    def __call__(self, x, y):
        return TwistedEdwardsCurve.Point(self.p, self.a, self.d, x, y)

    def __getitem__(self, x, y):
        return TwistedEdwardsCurve.Point(self.p, self.a, self.d, x, y)

    def _to_weierstrass_params(self):
        a = self.a
        d = self.d
        return self.F[-1] / self.F[48] * (a ** 2 + self.F[14] * a * d + d ** 2), \
               self.F[1] / self.F[864] * (a + d) * (-a ** 2 + self.F[34] * a * d - d ** 2)

    class Point(object):
        def __init__(self, p: tp.Union[int, bool, WeierstrassCurve.Point], a, d, x, y):
            if isinstance(p, bool):
                self.point = WeierstrassCurve.Point(True, 0, 0, 0, 0)
                return

            if isinstance(p, WeierstrassCurve.Point):
                self.point = p
                self.a = a
                self.d = d
                return

            self.p = p
            self.F = Zp(p)
            self.a = a
            self.d = d
            self.point = WeierstrassCurve.Point(p, *self._to_weierstrass_params(), *self._to_weierstrass(x, y))

        def _to_weierstrass_params(self):
            a = self.a
            d = self.d
            return self.F[-1] / self.F[48] * (a ** 2 + self.F[14] * a * d + d ** 2), \
                   self.F[1] / self.F[864] * (a + d) * (-a ** 2 + self.F[34] * a * d - d ** 2)

        def _to_weierstrass(self, x, y):
            a = self.a
            d = self.d
            return (self.F[5] * a + a * y - self.F[5] * d * y - d) / (self.F[12] - self.F[12] * y), \
                   (a + a * y - d * y - d) / (self.F[4] * x - self.F[4] * x * y)

        def _to_twistededwards(self, u, v):
            a = self.a
            d = self.d
            y = (self.F[5] * a - self.F[12] * u - d) / (-self.F[12] * u - a + self.F[5] * d)
            x = (a + a * y - d * y - d) / (self.F[4] * v - self.F[4] * v * y)
            return x, y

        def zero(self):
            return TwistedEdwardsCurve.Point(True, 0, 0, 0, 0)

        def is_zero(self):
            return self.point.is_zero()

        def is_valid(self):
            return self.point.is_valid()

        def __eq__(self, other):
            return self.point == other.point

        def __neg__(self):
            return TwistedEdwardsCurve.Point(-self.point, self.a, self.d, 0, 0)

        def __add__(self, other):
            return TwistedEdwardsCurve.Point(self.point + other.point, self.a, self.d, 0, 0)

        def __mul__(self, n):
            """p*n = p + p + ... + p"""
            return TwistedEdwardsCurve.Point(self.point * n, self.a, self.d, 0, 0)

        def __str__(self):
            return self.point.__str__()

        def get_x(self):
            return self.point.get_x()

        def get_y(self):
            return self.point.get_y()


def main():
    # source: https://neuromancer.sk/std/nist/P-256
    p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
    F = Zp(p)
    a = F[0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc]
    b = F[0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b]
    m = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
    p256 = WeierstrassCurve(p, a, b, m, 0)
    print(p256.F.p)
    print(p256.m)
    print(p256.n)
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

    # source: https://neuromancer.sk/std/gost/id-tc26-gost-3410-2012-512-paramSetC
    p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffdc7
    F = Zp(p)
    a = F[0x01]
    d = F[
        0x9e4f5d8c017d8d9f13a5cf3cdf5bfe4dab402d54198e31ebde28a0621050439ca6b39e0a515c06b304e2ce43e79e369e91a0cfc2bc2a22b4ca302dbb33ee7550]
    m = 0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc98cdba46506ab004c33a9ff5147502cc8eda9e7a769a12694623cef47f023ed
    gost512 = TwistedEdwardsCurve(p, a, d, m, 0)
    G = gost512(F[0x12], F[
        0x469af79d1fb1f5e16b99592b77a01e2a0fdfb0d01794368d9a56117f7b38669522dd4b650cf789eebf068c5d139732f0905622c04b2baae7600303ee73001a3d])


if __name__ == '__main__':
    main()
