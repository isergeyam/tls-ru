import binascii

from cipher.P_50_1_113_2016.hmacGOST import HMAC
from tools.utils import min_bytearray_big


# KDF_TREE_GOSTR3411_2012_256


class KDFTree256:
    def __init__(self, key: bytearray, label: str | bytearray, seed: bytearray, R: int):
        self.hmac = HMAC(key, 256)
        if isinstance(label, str):
            self.label = bytearray()
            self.label.extend(map(ord, label))
        else:
            self.label = label
        self.seed = seed
        self.R = R
        self.module = int(256 ** self.R)

    def change_key(self, key: bytearray):
        self.hmac.change_key(key)

    def __call__(self, L: int = 256):
        res = bytearray()
        index = 1
        l_bytes = min_bytearray_big(L)
        while len(res) * 8 < L:
            res.extend(self.kek(index, l_bytes))
            index += 1
        return res

    def kek(self, i: int, l_bytes: bytearray):
        message = bytearray(0)
        message.extend(i.to_bytes(self.R, 'big'))
        message.extend(self.label)
        message.extend([0])
        message.extend(self.seed)
        message.extend(l_bytes)
        return self.hmac.digest(message)
