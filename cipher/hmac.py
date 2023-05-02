from Streebog import *


class HMAC:
    def __init__(self, key: bytearray, mode: int):
        self.hasher = StreebogHasher(mode)

        self.k1, self.k2 = self.inner_keys(key)

    def __call__(self, key:bytearray):
        self.k1, self.k2 = self.inner_keys(key)
        return self

    def digest(self, message: bytearray):
        return self.hasher << (self.k2 + (self.hasher << (self.k1 + message) >> 0)) >> 0

    @staticmethod
    def inner_keys(key):
        ipad = int.from_bytes(b'\x36' * 64, 'big')
        opad = int.from_bytes(b'\x5c' * 64, 'big')
        key = int.from_bytes(key + bytearray.fromhex('00' * (64 - len(key))), 'big')
        k1 = bytearray((ipad ^ key).to_bytes(64, 'big'))
        k2 = bytearray((opad ^ key).to_bytes(64, 'big'))
        return k1, k2