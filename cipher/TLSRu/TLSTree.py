import binascii

from cipher.P_50_1_113_2016.KDF256 import KDF256
from cipher.Kuznechik import Kuznechik


class Diver:
    def __init__(self, key: bytearray, label: bytearray):
        self.kdf = KDF256(key)
        self.label = label

    def change_key(self, key: bytearray):
        self.kdf.change_key(key)

    def __call__(self, seed: bytearray):
        return self.kdf(self.label, seed)


class TLSTree:
    def __init__(self, key: bytearray, c1: bytearray, c2: bytearray, c3: bytearray):
        self.keys = [bytearray() for _ in range(4)]
        self.keys[0] = key
        self.labels = [bytearray(map(ord, 'level' + str(i + 1))) for i in range(3)]
        self.divers = []
        self.c = [int.from_bytes(c1, 'big'), int.from_bytes(c2, 'big'), int.from_bytes(c3, 'big')]
        self.seed = 0
        self.levels_in = [0 for _ in range(3)]
        self.set_divers()

    def set_divers(self):
        for i in range(3):
            self.divers.append(Diver(self.keys[i], self.labels[i]))
            self.levels_in[i] = self.c[i] & self.seed
            self.keys[i + 1] = self.divers[i](bytearray(self.levels_in[i].to_bytes(8, 'big')))

    def __call__(self, index: int):
        self.seed = index
        self.recompute()
        return self.keys[3]

    def recompute(self):
        flag = False
        for i in range(3):
            if flag or self.levels_in[i] != self.c[i] & self.seed:
                self.levels_in[i] = self.c[i] & self.seed
                self.keys[i + 1] = self.divers[i](bytearray(self.levels_in[i].to_bytes(8, 'big')))
                if i != 2:
                    self.divers[i + 1].change_key(self.keys[i + 1])
                flag = True

    def change_key(self, key: bytearray):
        self.keys[0] = key
        for i in range(3):
            self.divers[i].change_key(self.keys[i])
            self.levels_in[i] = self.c[i] & self.seed
            self.keys[i + 1] = self.divers[i](bytearray(self.levels_in[i].to_bytes(8, 'big')))


class KuznechikOnTree:
    def __init__(self, key: bytearray):
        self.tlstree = newTLSTreeKuznechik(key)
        self.index = 0
        self.kuznechik = Kuznechik(self.tlstree(self.index))

    def __call__(self, index):
        if self.index // 64 != index // 64:
            self.kuznechik.ChangeKey(self.tlstree(index))
            self.index = index
        return self.kuznechik


def newTLSTreeKuznechik(key: bytearray):
    c1_kuz = bytearray.fromhex("FFFFFFFF00000000")
    c2_kuz = bytearray.fromhex("FFFFFFFFFFF80000")
    c3_kuz = bytearray.fromhex("FFFFFFFFFFFFFFC0")

    return TLSTree(key, c1_kuz, c2_kuz, c3_kuz)


if __name__ == "__main__":
    my_key = bytearray.fromhex("""
    FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
    FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
    """)
    my_label = bytearray(map(ord, 'level1'))

    diver = Diver(my_key, my_label)
    res = diver(bytearray(8))
    print(binascii.hexlify(res))

    tree = newTLSTreeKuznechik(my_key)

    res = tree(0)

    print(binascii.hexlify(res))

    res = tree(1)

    print(binascii.hexlify(res))

    res = tree(63)

    print(binascii.hexlify(res))

    res = tree(64)

    print(binascii.hexlify(res))

    tree.change_key(my_key)

    res = tree(0)

    print(binascii.hexlify(res))

    res = tree(1)

    print(binascii.hexlify(res))

    res = tree(63)

    print(binascii.hexlify(res))

    res = tree(64)

    print(binascii.hexlify(res))
