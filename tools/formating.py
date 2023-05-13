def byte_from_hex(value):
    return bytearray.fromhex(value)


def int_from_hex_big(value):
    return int.from_bytes(bytearray.fromhex(value), 'big')


def int_from_hex_little(value):
    return int.from_bytes(bytearray.fromhex(value), 'little')