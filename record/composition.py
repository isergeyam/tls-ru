from cipher.vko import VKO
from TLSTree import KDF256
from Streebog import StreebogHasher
from cipher.prf import PRF
import binascii


def get_Qeph_PSExp(r_s, r_c, Q_s, PS):
    pass


def client_verify_data(MS, HM, mode):
    hasher = StreebogHasher(mode)
    return PRF(MS, mode).digest(bytearray('client finished', 'ascii'), hasher << HM >> 0)


def server_verify_data(MS, HM, mode):
    hasher = StreebogHasher(mode)
    return PRF(MS, mode).digest(bytearray('server finished', 'ascii'), hasher << HM >> 0)


def KEG(d: int, Q, h, curve):
    vko = VKO(curve, 512)  # curve это кривая, не знаю как ее брать по Qs
    r = int.from_bytes(h[0: 16], 'big')
    print(binascii.hexlify(bytearray(r.to_bytes(32, 'big'))))
    UKM = 1 if r == 0 else r

    print("kekw", binascii.hexlify(bytearray(UKM.to_bytes(32, 'big'))))
    return vko.digest(d, Q, UKM)
