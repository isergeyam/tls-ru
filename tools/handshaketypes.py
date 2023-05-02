import binascii

from tools.result import Result, fbyteresult, variant
from collections import OrderedDict

import time


def TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC():
    return fbyteresult("ff89")


def TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC():
    return fbyteresult("ff88")


def Sesion_id(value=""):
    return Result("bytes", bytearray.fromhex(value), 1, len(value))


def CipherSuites(values):
    return Result("array", values, 2, 0)


def CompressionMethods(values=None):
    if values is None:
        values = [fbyteresult("00")]
    return Result("array", values, len(values), 1)


def Version(major="03", minor="03"):
    value = OrderedDict()
    value["major"] = fbyteresult(major)
    value["minor"] = fbyteresult(minor)
    return Result("fdict", value, 2, 0)


def extended_master_secret():
    return variant(23, 2, Result("bytes", bytearray(), 2, 0))


def renegotiation_info(value=bytearray(1)):
    return variant(65281, 2, Result("bytes", value, 2, 0))


def gostr34112012_256():
    return fbyteresult("EE")


def gostr34112012_512():
    return fbyteresult("EF")


def gostr34102012_256():
    return fbyteresult("EE")


def gostr34102012_512():
    return fbyteresult("EF")


def gostrHS_256():
    value = OrderedDict()
    value["hash"] = gostr34112012_256()
    value["signature"] = gostr34102012_256()
    return Result("fdict", value, 0, 2)


def gostrHS_512():
    value = OrderedDict()
    value["hash"] = gostr34112012_512()
    value["signature"] = gostr34102012_512()
    return Result("fdict", value, 0, 2)


def Supported_signature_algorithms(value=None):
    if value is None:
        value = [gostrHS_256(), gostrHS_512()]
    return Result("array", value, 2, len(value) * 2)


def signature_algorithms(value=Supported_signature_algorithms()):
    dic = OrderedDict()
    dic["supported_signature_algorithms"] = value
    return variant(13, 2, Result("dict", dic, 2, 0))


def ClientHello(random, version=Version(), session_id=Sesion_id(),
                cipher_suites=None,
                extensions=None):
    if cipher_suites is None:
        cipher_suites = [TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC(), TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC()]
    if extensions is None:
        extensions = [signature_algorithms(), renegotiation_info(), extended_master_secret()]
    d = OrderedDict()
    d["client_version"] = version
    d["random"] = Result("fbytes", random, 0, 32)
    d["session_id"] = session_id
    d["cipher_suites"] = CipherSuites(cipher_suites)
    d["compression_methods"] = CompressionMethods()
    d["extensions"] = Result("array", extensions, 2, 0)
    return variant(1, 1, Result("dict", d, 3))


def ServerHello(random, version=Version(), session_id=Sesion_id(),
                cipher_suites=None,
                extensions=None):
    if cipher_suites is None:
        cipher_suites = TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC()
    if extensions is None:
        extensions = [renegotiation_info(), extended_master_secret()]
    d = OrderedDict()
    d["server_version"] = version
    d["random"] = Result("fbytes", random, 0, 32)
    d["session_id"] = session_id
    d["cipher_suites"] = cipher_suites
    d["compression_methods"] = fbyteresult("00")
    d["extensions"] = Result("array", extensions, 2, 0)

    return variant(2, 1, Result("dict", d, 3))


def CertificateSingle(value):
    d = OrderedDict()
    d["body"] = Result("fbytes", value, 0, 0)

    return Result("dict", d, 3, 0)


def CertificateList(values):
    value = [CertificateSingle(c) for c in values]
    return Result("array", value, 3, 0)


def Certificate(values):
    d = OrderedDict()
    d["body"] = CertificateList(values)
    return variant(11, 1, Result("dict", d, 3))


def get_name_from_cert(cert):
    return cert["body"][0]["certificate"][0][5][0][0][1].value


def get_point_from_cert(cert):
    xy = cert["body"][0]["certificate"][0][6][1].value
    return xy[4:68], xy[68:]

def get_curve_from_cert(cert):
    return cert["body"][0]["certificate"][0][6][0][1][0].to_bytes()

def test_a():
    res = ClientHello(bytearray().fromhex("933ea21ec3802a561550ec78d6ed51ac2439d7e749c31bc3a3456165889684ca"),
                      cipher_suites=[TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC(),
                                     TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC()])

    mybuffer = bytearray.fromhex(
        """
        01 00 00 40 03 03 93 3E A2 1E C3 80 2A 56 15 50
        EC 78 D6 ED 51 AC 24 39 D7 E7 49 C3 1B C3 A3 45
        61 65 88 96 84 CA 00 00 04 FF 88 FF 89 01 00 00
        13 00 0D 00 06 00 04 EE EE EF EF FF 01 00 01 00
        00 17 00 00
        """)

    assert mybuffer == res.to_bytes()

    mybuffer = bytearray.fromhex(
        """
        02 00 00 41 03 03 93 3E A2 1E 49 C3 1B C3 A3 45
        61 65 88 96 84 CA A5 57 6C E7 92 4A 24 F5 81 13
        80 8D BD 9E F8 56 10 C3 80 2A 56 15 50 EC 78 D6
        ED 51 AC 24 39 D7 E7 FF 88 00 00 09 FF 01 00 01
        00 00 17 00 00
        """)

    res = ServerHello(bytearray().fromhex("933EA21E49C31BC3A3456165889684CAA5576CE7924A24F58113808DBD9EF856"),
                      session_id=Sesion_id("C3802A561550EC78D6ED51AC2439D7E7"),
                      cipher_suites=TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC())

    print(binascii.hexlify(res.to_bytes()))
    print(binascii.hexlify(mybuffer))

    assert mybuffer == res.to_bytes()

    cert = bytearray.fromhex("""30 82 02 B2 30 82 02 61 A0 03 02 01 02 02 0A 28 A2 90 E3 00 00 00 D8 D1 42 30 08 06 06 2A 85 03 02 02 03 30 3A 31 12 30 10 06 0A 09 92 26 89 93 F2 2C 64 01 19 16 02 72 75 31 12 30 10 06 0A 09 92 26 89 93 F2 2C 64 01 19 16 02 63 70 31 10 30 0E 06 03 55 04 03 13 07 74 65 73 74 2D 63 61 30 1E 17 0D 31 37 31 30 32 34 30 32 35 30 35 36 5A 17 0D 32 37 31 30
                32 34 30 39 33 30 35 36 5A 30 21 31 1F 30 1D 06
                03 55 04 03 13 16 53 65 72 76 65 72 54 4C 53 31
                32 54 65 73 74 53 61 6D 70 6C 65 73 30 68 30 21
                06 08 2A 85 03 07 01 01 01 01 30 15 06 09 2A 85
                03 07 01 02 01 01 01 06 08 2A 85 03 07 01 01 02
                02 03 43 00 04 40 FD 13 E3 20 DC 43 F4 71 23 60
                E1 1F 8A 50 E0 94 07 47 45 72 12 E9 56 6E 02 CB
                4C 60 E3 D6 3E C0 EC 25 10 9A E3 99 C7 69 49 6D
                A4 89 29 85 1A 8D 9C 47 C8 FA 0A 8E E7 20 B7 DB
                A2 91 94 57 4D 99 A3 82 01 59 30 82 01 55 30 13
                06 03 55 1D 25 04 0C 30 0A 06 08 2B 06 01 05 05
                07 03 01 30 0E 06 03 55 1D 0F 01 01 FF 04 04 03
                02 04 F0 30 1D 06 03 55 1D 0E 04 16 04 14 B0 90
                04 86 FC 71 C5 91 5A CA 9B 6B 36 1C 18 A8 37 14
                35 1B 30 1F 06 03 55 1D 23 04 18 30 16 80 14 9E
                03 F0 B8 9C FC 60 DC 8A 18 1E E8 00 DF A8 5B 32
                CD 73 76 30 3F 06 03 55 1D 1F 04 38 30 36 30 34
                A0 32 A0 30 86 2E 68 74 74 70 3A 2F 2F 76 6D 2D
                74 65 73 74 2D 63 61 2E 63 70 2E 72 75 2F 43 65
                72 74 45 6E 72 6F 6C 6C 2F 74 65 73 74 2D 63 61
                2E 63 72 6C 30 81 AC 06 08 2B 06 01 05 05 07 01
                01 04 81 9F 30 81 9C 30 4B 06 08 2B 06 01 05 05
                07 30 02 86 3F 68 74 74 70 3A 2F 2F 76 6D 2D 74
                65 73 74 2D 63 61 2E 63 70 2E 72 75 2F 43 65 72
                74 45 6E 72 6F 6C 6C 2F 76 6D 2D 74 65 73 74 2D
                63 61 2E 63 70 2E 72 75 5F 74 65 73 74 2D 63 61
                2E 63 72 74 30 4D 06 08 2B 06 01 05 05 07 30 02
                86 41 66 69 6C 65 3A 2F 2F 5C 5C 76 6D 2D 74 65
                73 74 2D 63 61 2E 63 70 2E 72 75 5C 43 65 72 74
                45 6E 72 6F 6C 6C 5C 76 6D 2D 74 65 73 74 2D 63
                61 2E 63 70 2E 72 75 5F 74 65 73 74 2D 63 61 2E
                63 72 74 30 08 06 06 2A 85 03 02 02 03 03 41 00
                93 30 50 11 50 42 80 3B 6F DD 1D 99 6A 75 0A C8
                DA 2C 3E F2 28 47 5E D3 FB C7 9A 3E A1 C7 D5 80
                AE 08 D0 81 F3 14 B4 88 09 BD 2C D4 B5 8F A8 4C
                B2 B6 66 11 FD 6C 0A 84 BE 59 25 3D 18 87 CC 02
        """)

    res = Certificate([cert])

    print(res)

    print(binascii.hexlify(res.to_bytes()))


def test_b():
    res = ClientHello(bytearray().fromhex("933ea21ec3802a561550ec78d6ed51ac2439d7e749c31bc3a3456165889684ca"),
                      cipher_suites=[TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC(),
                                     TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC()])

    mybuffer = bytearray.fromhex(
        """
        01 00 00 40 03 03 93 3E A2 1E C3 80 2A 56 15 50
        EC 78 D6 ED 51 AC 24 39 D7 E7 49 C3 1B C3 A3 45
        61 65 88 96 84 CA 00 00 04 FF 88 FF 89 01 00 00
        13 00 0D 00 06 00 04 EE EE EF EF FF 01 00 01 00
        00 17 00 00
        """)

    assert mybuffer == res.to_bytes()

    mybuffer = bytearray.fromhex(
        """
        02 00 00 41 03 03 93 3E A2 1E 49 C3 1B C3 A3 45
        61 65 88 96 84 CA A5 57 6C E7 92 4A 24 F5 81 13
        80 8D BD 9E F8 56 10 C3 80 2A 56 15 50 EC 78 D6
        ED 51 AC 24 39 D7 E7 FF 89 00 00 09 FF 01 00 01
        00 00 17 00 00
        """)

    res = ServerHello(bytearray().fromhex("933EA21E49C31BC3A3456165889684CAA5576CE7924A24F58113808DBD9EF856"),
                      session_id=Sesion_id("C3802A561550EC78D6ED51AC2439D7E7"))

    print(binascii.hexlify(res.to_bytes()))
    print(binascii.hexlify(mybuffer))

    assert mybuffer == res.to_bytes()


def generate_random():
    sec = int(time.time())
    res = bytearray(sec.to_bytes(4, 'big'))
    res.extend(bytearray(28))
    return res


if __name__ == "__main__":
    test_a()
    test_b()
