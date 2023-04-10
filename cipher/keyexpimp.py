from omac import OMAC
from Kuznechik import Kuznechik
from ctr import Ctr
import binascii


class KExpImp15(object):
    def __init__(self, KExpMac, KExpEnc, IV):
        self.KExpMac = KExpMac
        self.KExpEnc = KExpEnc
        self.IV = IV

        self.kuz_mac = Kuznechik(self.KExpMac)
        self.n = self.kuz_mac.n
        self.omac = OMAC(self.kuz_mac, self.n)

        self.kuz_enc = Kuznechik(self.KExpEnc)
        self.ctr = Ctr(self.kuz_enc, self.n)

        self.n //= 8
        assert len(self.IV) == self.n // 2

    def exp(self, K):
        print(binascii.hexlify(self.IV + K))
        keymac = self.omac.mac(self.IV + K)
        kexp = self.ctr.encode(self.IV, K + keymac)
        return kexp

    def imp(self, KExp):
        kexp = self.ctr.decode(self.IV, KExp)
        k = kexp[:len(self.KExpMac)]
        kmac = kexp[len(self.KExpMac):]
        if kmac != self.omac.mac(self.IV + k):
            raise RuntimeError("mac does not match")
        return k


if __name__ == "__main__":
    K = bytearray.fromhex("""
    88 99 AA BB CC DD EE FF 00 11 22 33 44 55 66 77 
    FE DC BA 98 76 54 32 10 01 23 45 67 89 AB CD EF
    """)
    KExpMac = bytearray.fromhex("""
    08 09 0A 0B 0C 0D 0E 0F 00 01 02 03 04 05 06 07 
    10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F
    """)
    KExpEnc = bytearray.fromhex("""
    20 21 22 23 24 25 26 27 28 29 2A 2B 2C 2D 2E 2F 
    38 39 3A 3B 3C 3D 3E 3F 30 31 32 33 34 35 36 37
    """)
    IV = bytearray.fromhex("09 09 47 2D D9 F2 6B E8")
    KExp = bytearray.fromhex("""
    E3 61 84 E8 4E 8D 73 6F F3 6C C2 E5 AE 06 5D C6 
    56 B2 3C 20 F5 49 B0 2F DF F8 8E 1F 3F 30 D8 C2 
    9A 53 F3 CA 55 4D BA D8 0D E1 52 B9 A4 62 5B 32
    """)
    kexpimp = KExpImp15(KExpMac, KExpEnc, IV)
    kexp = kexpimp.exp(K)
    assert K == kexpimp.imp(kexp)
    # assert KExp == kexpimp.exp(K)
    # assert K == kexpimp.imp(KExp)
