from TLSTree import TLSTree


def newTLSTreeKuznechik(key: bytearray):
    c1_kuz = bytearray.fromhex("FFFFFFFF00000000")
    c2_kuz = bytearray.fromhex("FFFFFFFFFFF80000")
    c3_kuz = bytearray.fromhex("FFFFFFFFFFFFFFC0")

    return TLSTree.TLSTree(key, c1_kuz, c2_kuz, c3_kuz)
