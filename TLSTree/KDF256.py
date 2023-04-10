from hmacGOST import HMAC
import binascii


def kdf256(key: bytearray, label: bytearray, seed: bytearray):
    hmac = HMAC(key, 256)
    message = bytearray(0)
    message.extend([1])
    message.extend(label)
    message.extend([0])
    message.extend(seed)
    message.extend([1])
    message.extend([0])
    return hmac.digest(message)


class KDF256:
    def __init__(self, key: bytearray):
        self.hmac = HMAC(key, 256)

    def __call__(self, label: bytearray, seed: bytearray):
        message = bytearray(0)
        message.extend([1])
        message.extend(label)
        message.extend([0])
        message.extend(seed)
        message.extend([1])
        message.extend([0])
        return self.hmac.digest(message)


if __name__ == "__main__":
    my_key = bytearray.fromhex("""
    00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
    10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f
    """)

    my_label = bytearray.fromhex("26 bd b8 78")
    my_seed = bytearray.fromhex("af 21 43 41 45 65 63 78")

    res = kdf256(my_key, my_label, my_seed)
    print(binascii.hexlify(res))
    exp = bytearray.fromhex("""
    a1 aa 5f 7d e4 02 d7 b3 d3 23 f2 99 1c 8d 45 34
    01 31 37 01 0a 83 75 4f d0 af 6d 7c d4 92 2e d9
    """)

    kdf = KDF256(my_key)

    res = kdf(my_label, my_seed)
    print(binascii.hexlify(res))

