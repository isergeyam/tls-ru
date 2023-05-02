"""
Module provides the realization of Z/p where p is prime.
"""


class Zp(object):
    def __init__(self, p, check=False):
        check and Zp._check_prime(p)
        self.p = p

    def __call__(self, val):
        return Zp.Element(val, self.p)

    def __getitem__(self, val):
        return Zp.Element(val, self.p)

    def __len__(self):
        return self.p

    def __iter__(self):
        elements = (self(i) for i in range(self.p))
        return elements

    def __reversed__(self):
        elements = (self(i) for i in range(self.p)[::-1])
        return elements

    def __str__(self):
        return 'Z/%d' % self.p

    def __repr__(self):
        return 'Z/%d' % self.p

    def get_elements(self):
        elements = [self(i) for i in range(self.p)]
        return tuple(elements)

    @staticmethod
    def _check_prime(p):
        if p <= 1:
            raise Exception('p should be prime')
        for i in range(2, int(p ** 0.5) + 1):
            if p % i == 0:
                raise Exception('p should be prime')

    class Element(object):
        def __init__(self, val, p):
            self.p = p
            self.val = val % self.p

        def __eq__(self, other):
            return self.val == other.val

        def __ne__(self, other):
            return self.val != other.val

        def __neg__(self):
            return Zp.Element(self.p - self.val, self.p)

        def __add__(self, other):
            return Zp.Element(self.val + other.val, self.p)

        def __sub__(self, other):
            return Zp.Element(self.val + (self.p - other.val), self.p)

        def __mul__(self, other):
            return Zp.Element(self.val * other.val, self.p)

        def __truediv__(self, other):
            return self * ~other

        def __pow__(self, other):
            if other >= 0:
                return Zp.Element(self.val ** other, self.p)
            else:
                return ~Zp.Element(self.val ** (-other), self.p)

        def __invert__(self):
            return Zp.Element(Zp.Element._inv(self.val, self.p), self.p)

        def __repr__(self):
            return str(self.val)

        def __str__(self):
            return str(self.val)

        def __int__(self):
            return self.val

        @staticmethod
        def _egcd(a, b):
            """extended GCD
            returns: (s, t, gcd) as a*s + b*t == gcd
            >>> s, t, gcd = _egcd(a, b)
            >>> assert a % gcd == 0 and b % gcd == 0
            >>> assert a * s + b * t == gcd
            """
            s0, s1, t0, t1 = 1, 0, 0, 1
            while b > 0:
                q, r = divmod(a, b)
                a, b = b, r
                s0, s1, t0, t1 = s1, s0 - q * s1, t1, t0 - q * t1
                pass
            return s0, t0, a

        @staticmethod
        def _inv(n, q):
            """div on PN modulo a/b mod q as a * inv(b, q) mod q
            >>> assert n * _inv(n, q) % q == 1
            """
            # n*inv % q = 1 => n*inv = q*m + 1 => n*inv + q*-m = 1
            # => egcd(n, q) = (inv, -m, 1) => inv = egcd(n, q)[0] (mod q)
            if n == 0:
                raise Exception('no invert for 0')
            return Zp.Element._egcd(n, q)[0] % q
