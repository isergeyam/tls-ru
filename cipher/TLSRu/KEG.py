import binascii

from cipher.P_50_1_113_2016.vko import VKO
from cipher.P_50_1_113_2016.kdf_tree256 import KDFTree256


class KEG:
    def __init__(self, curve, mod=512):
        self.mod = mod
        self.curve = curve
        self.vko = VKO(curve, mod)

    def __call__(self, d: int, Q, h):
        r = int.from_bytes(h[0: 16], 'big')
        UKM = 1 if r == 0 else r
        if self.mod == 512:
            return self.vko.digest(d, Q, UKM)
        else:
            Kexp = self.vko.digest(d, Q, UKM)
            print(binascii.hexlify(Kexp))
            seed = h[16: 24]
            kdf = KDFTree256(Kexp, "kdf tree", seed, 1)
            return kdf(512)
