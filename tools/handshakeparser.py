from tools.myparser import Parser
import binascii
import io
from collections import namedtuple

import asyncio

from tools.utils import new_io_bytes_from_string


def HandshakeParser():
    parser = Parser()

    # Version

    parser.remember("ProtocolVersion",
                    "fdict(major, fbytes(1), minor, fbytes(1))")

    # Random

    parser.remember("Random", "fbytes(32)")

    # SesionID

    parser.remember("SessionID", "bytes(1)")

    # CipherSuites

    parser.remember("CipherSuite", "fbytes(2)")
    parser.remember("CipherSuites", "array(2, CipherSuite)")

    # CompressionMethods

    parser.remember("CompressionMethod", "fbytes(1)")
    parser.remember("CompressionMethods", "array(1, CompressionMethod)")

    # Extension
    parser.remember("HashAlgorithm", "fbytes(1)")
    parser.remember("SignatureAlgorithm", "fbytes(1)")
    parser.remember("SignatureAndHashAlgorithm",
                    "fdict(hash, HashAlgorithm, signature, SignatureAlgorithm)")
    parser.remember("Supported_signature_algorithms", "array(2, SignatureAndHashAlgorithm)")
    parser.remember("Signature_algorithms", "dict(2, supported_signature_algorithms, Supported_signature_algorithms)")
    parser.remember("Extended_master_secret", "bytes(2)")

    parser.remember("renegotiated_connection", "bytes(1)")

    parser.remember("RenegotiationInfo", "array(2, renegotiated_connection)")

    parser.remember(
        "Extension", "variant(2, 13, Signature_algorithms, 23, Extended_master_secret, 65281, RenegotiationInfo)")

    # parser.remember("ASN1Cert", "bytes(3)")
    # parser.remember("Certificate", "array(3, ASN1Cert)")

    parser.remember("ClientCertificateType", "array(1, fbytes(1))")
    parser.remember("DistinguishedName", "bytes(2)")
    parser.remember("CertificateRequest",
                    """
                    dict(3,
                    certificate_types, ClientCertificateType,
                    supported_signature_algorithms, Supported_signature_algorithms,
                    certificate_authorities, DistinguishedName
                    )""")

    parser.remember("ClientHelloBody",
                    """
                    dict(3,
                    client_version, ProtocolVersion,
                    random, Random,
                    session_id, SessionID,
                    cipher_suites, array(2, CipherSuite),
                    compression_methods, array(1, CompressionMethod),
                    extensions, array(2, Extension)
                    )""")

    parser.remember("ServerHelloBody",
                    """
                    dict(3,
                    server_version, ProtocolVersion,
                    random, Random,
                    session_id, SessionID,
                    cipher_suite, CipherSuite,
                    compression_method,  CompressionMethod,
                    extensions, array(2, Extension)
                    )""")

    parser.remember("Certificate",
                    """
                    dict(3,
                    certificate, ASN
                    )""")

    parser.remember("CertificateList",
                    """
                    array(3, Certificate )
                    """)

    parser.remember("CertificateBody",
                    """
                    dict(3,
                    body, CertificateList )
                    """)

    parser.remember("ServerHelloDone", "dict(3)")

    parser.remember("ClientKeyExchange", "dict(3, exchange_keys, ASN)")

    parser.remember("CertificateVerify", "dict(3, algorithm, SignatureAndHashAlgorithm, signature, bytes(2))")

    parser.remember("Finished", "dict(3, verify_data, fbytes(32))")

    parser.remember("Handshake", """variant(1,
                    0, fbytes(0),
                    1, ClientHelloBody,
                    2, ServerHelloBody,
                    11, CertificateBody,
                    13, CertificateRequest,
                    14, ServerHelloDone,
                    15, CertificateVerify,
                    16, ClientKeyExchange,
                    20, Finished
                    )""")

    mypattern = "Handshake"
    mypytternstream = io.StringIO(mypattern)

    return parser.parse(mypytternstream)


Variant = namedtuple("Variant", ["variant_type", "data"])


def compare_result(result, expected):
    if isinstance(expected, Variant):
        assert result.variant_type == expected.variant_type
        compare_result(result.value, expected.data)
    elif isinstance(expected, dict):
        for k, v in expected.items():
            compare_result(result[k], v)
    elif isinstance(expected, list):
        for i, v in enumerate(expected):
            compare_result(result[i], v)
    else:
        assert result.value == expected


async def test_client_hello():
    reader = HandshakeParser()

    mybuffer_hex = """
        01 00 00 40 03 03 93 3E A2 1E C3 80 2A 56 15 50
        EC 78 D6 ED 51 AC 24 39 D7 E7 49 C3 1B C3 A3 45
        61 65 88 96 84 CA 00 00 04 FF 88 FF 89 01 00 00
        13 00 0D 00 06 00 04 EE EE EF EF FF 01 00 01 00
        00 17 00 00
        """
    mybufferstream = new_io_bytes_from_string(mybuffer_hex)
    res = await reader(mybufferstream)
    expected = Variant \
        (1,
         {
             "client_version": {
                 "major": bytes.fromhex('03'),
                 "minor": bytes.fromhex('03'),
             },
             "random": bytes.fromhex("933EA21EC3802A561550EC78D6ED51AC2439D7E749C31BC3A3456165889684CA"),
             "session_id": b"",
             "cipher_suites": [bytes.fromhex("ff88"), bytes.fromhex("ff89")],
             "compression_methods": [bytes.fromhex("00")],
             "extensions": [
                 Variant(0x000d, {
                     "supported_signature_algorithms":
                         [{"hash": bytes.fromhex("ee"), "signature": bytes.fromhex("ee")},
                          {"hash": bytes.fromhex("ef"), "signature": bytes.fromhex("ef")}]
                 }),
                 Variant(0xff01, [b""]),
                 Variant(0x0017, b""),
             ]
         })
    compare_result(res, expected)


async def test_server_hello():
    reader = HandshakeParser()

    mybuffer = """
        02 00 00 41 03 03 93 3E A2 1E 49 C3 1B C3 A3 45
        61 65 88 96 84 CA A5 57 6C E7 92 4A 24 F5 81 13
        80 8D BD 9E F8 56 10 C3 80 2A 56 15 50 EC 78 D6
        ED 51 AC 24 39 D7 E7 FF 88 00 00 09 FF 01 00 01
        00 00 17 00 00
        """

    mybufferstream = new_io_bytes_from_string(mybuffer)
    res = await reader(mybufferstream)
    expected = Variant \
        (2,
         {
             "server_version": {
                 "major": bytes.fromhex('03'),
                 "minor": bytes.fromhex('03'),
             },
             "random": bytes.fromhex("933EA21E49C31BC3A3456165889684CAA5576CE7924A24F58113808DBD9EF856"),
             "session_id": bytes.fromhex("C3802A561550EC78D6ED51AC2439D7E7"),
             "cipher_suite": bytes.fromhex("ff88"),
             "compression_method": bytes.fromhex("00"),
             "extensions": [
                 Variant(0xff01, [b""]),
                 Variant(0x0017, b""),
             ]
         })
    compare_result(res, expected)


async def test_certificate_request():
    reader = HandshakeParser()

    mybuffer = """
        0D00000B02EEEF0004EEEEEFEF0000
        """

    mybufferstream = new_io_bytes_from_string(mybuffer)
    res = await reader(mybufferstream)
    expected = Variant \
        (0x0D,
         {
             "certificate_types": [bytes.fromhex("EE"), bytes.fromhex("EF")],
             "supported_signature_algorithms":
                 [{"hash": bytes.fromhex("ee"), "signature": bytes.fromhex("ee")},
                  {"hash": bytes.fromhex("ef"), "signature": bytes.fromhex("ef")}],
             "certificate_authorities": []
         })
    compare_result(res, expected)


async def test_server_hello_done():
    reader = HandshakeParser()

    mybuffer = """
        0E 00 00 00
        """

    mybufferstream = new_io_bytes_from_string(mybuffer)
    res = await reader(mybufferstream)
    expected = Variant \
        (0x0E, dict())
    compare_result(res, expected)


async def test_client_key_exchange():
    reader = HandshakeParser()

    key_exchange_data = """
        30819404282536556CCDAC34914FD115 4C2A9F9E5D7FDE774350FD66907A2021 A9A1DF8C982F30CF2BE4CF91AF306830 2106082A85030701010101301506092A 850307010201010106082A8503070101 020203430004408D490F4CB030E23974 E218C2787312BED9F361377CCCF52A7E
        73856C2A19D98600CEC1B836C6405B24 1BA7CD8C085E2DEC6C4E0A61D972F1D9 8FE4B8760E1971
        """
    mybuffer = "10000097" + key_exchange_data

    mybufferstream = new_io_bytes_from_string(mybuffer)
    res = await reader(mybufferstream)
    print(res)
    expected = Variant \
        (0x10, bytearray.fromhex(key_exchange_data))

    compare_result(res, expected)


async def test_certificate_verify():
    reader = HandshakeParser()

    mybuffer = """
    0F000044EEEE0040
    F71F4362455BC55BA89A8FAF018288EC
00B32717482E7624B257D9797C8FF602 7996D84627609FF8625637DFAEF4A648 C4A3517CA65E5BA3794DC5997839EF1A 
    """

    mybufferstream = new_io_bytes_from_string(mybuffer)
    res = await reader(mybufferstream)
    expected = Variant \
        (0x0F, {
            "algorithm": {"hash": bytes.fromhex("ee"), "signature": bytes.fromhex("ee")},
            "signature": bytes.fromhex("""
            F71F4362455BC55BA89A8FAF018288EC
00B32717482E7624B257D9797C8FF602 7996D84627609FF8625637DFAEF4A648 C4A3517CA65E5BA3794DC5997839EF1A
            """)
        })
    compare_result(res, expected)


async def test_finished():
    reader = HandshakeParser()
    verify_data = """
    2A75BE8DB1281820C3E91C3ACFB356E5
    38BDC640DA0A81635986F3D28C391521
    """

    mybuffer = """
        14000020
        2A75BE8DB1281820C3E91C3ACFB356E5
        38BDC640DA0A81635986F3D28C391521 
        """

    mybufferstream = new_io_bytes_from_string(mybuffer)
    res = await reader(mybufferstream)
    expected = Variant(0x14, {"verify_data": bytearray.fromhex(verify_data)})
    compare_result(res, expected)


# def test_certificate():
#     reader = HandshakeParser()
#     cert_str = """0B0002BC0002B90002B6308202B23082  0261A003020102020A28A290E3000000  D8D142300806062A8503020203303A31  123010060A0992268993F22C64011916
#  02727531123010060A0992268993F22C  640119160263703110300E0603550403  1307746573742D6361301E170D313731  3032343032353035365A170D32373130  32343039333035365A3021311F301D06  035504031316536572766572544C5331  325465737453616D706C657330683021  06082A85030701010101301506092A85  0307010201010106082A850307010102  020343000440FD13E320DC43F4712360  E11F8A50E0940747457212E9566E02CB  4C60E3D63EC0EC25109AE399C769496D  A48929851A8D9C47C8FA0A8EE720B7DB  A29194574D99A3820159308201553013  0603551D25040C300A06082B06010505  070301300E0603551D0F0101FF040403  0204F0301D0603551D0E04160414B090  0486FC71C5915ACA9B6B361C18A83714  351B301F0603551D230418301680149E  03F0B89CFC60DC8A181EE800DFA85B32
#  CD7376303F0603551D1F043830363034  A032A030862E687474703A2F2F766D2D  746573742D63612E63702E72752F4365  7274456E726F6C6C2F746573742D6361  2E63726C3081AC06082B060105050701  0104819F30819C304B06082B06010505  073002863F687474703A2F2F766D2D74  6573742D63612E63702E72752F436572  74456E726F6C6C2F766D2D746573742D  63612E63702E72755F746573742D6361  2E637274304D06082B06010505073002  864166696C653A2F2F5C5C766D2D7465  73742D63612E63702E72755C43657274  456E726F6C6C5C766D2D746573742D63
#  612E63702E72755F746573742D63612E  637274300806062A8503020203034100  933050115042803B6FDD1D996A750AC8  DA2C3EF228475ED3FBC79A3EA1C7D580  AE08D081F314B48809BD2CD4B58FA84C
#  B2B66611FD6C0A84BE59253D1887CC02
#     """
#     mybuffer = bytearray.fromhex(cert_str)
#     print(len(mybuffer))
#     mybufferstream = new_io_bytes_from_string(mybuffer)
#     res = await reader(mybufferstream)
#     expected = Variant(0x0B, [bytes.fromhex(cert_str[46:])])
#     compare_result(res, expected)


async def test_handshake():
    reader = HandshakeParser()

    mybuffer = """
        01 00 00 40 03 03 93 3E A2 1E C3 80 2A 56 15 50
        EC 78 D6 ED 51 AC 24 39 D7 E7 49 C3 1B C3 A3 45
        61 65 88 96 84 CA 00 00 04 FF 88 FF 89 01 00 00
        13 00 0D 00 06 00 04 EE EE EF EF FF 01 00 01 00
        00 17 00 00
        """
    mybufferstream = new_io_bytes_from_string(mybuffer)
    res = await reader(mybufferstream)
    print(res)
    print("handshake type:", res.variant_type)
    print("version major :", res["client_version"]["major"].value)
    print("version minor :", res["client_version"]["minor"].value)
    print("random :", binascii.hexlify(res["random"].value))
    print("sessionID :", binascii.hexlify(res["session_id"].value))
    for ciphersuite in res["cipher_suites"]:
        print("ciphersuite : ", binascii.hexlify(ciphersuite.value))

    print(res["cipher_suites"][0].value)

    for ciphersuite in res["compression_methods"]:
        print("compression_method : ", binascii.hexlify(ciphersuite.value))

    for ciphersuite in res["extensions"]:
        print("extension type :", ciphersuite.variant_type)
        print("extensions : ", ciphersuite.value)

    print(res.update_size())

    buf = io.BytesIO()

    print(res.write(buf))
    buf.seek(0)
    print(binascii.hexlify(buf.read(res.get_full_size())))
    print(binascii.hexlify(bytearray.fromhex(mybuffer)))

    mybuffer = """
        02 00 00 41 03 03 93 3E A2 1E 49 C3 1B C3 A3 45
        61 65 88 96 84 CA A5 57 6C E7 92 4A 24 F5 81 13
        80 8D BD 9E F8 56 10 C3 80 2A 56 15 50 EC 78 D6
        ED 51 AC 24 39 D7 E7 FF 88 00 00 09 FF 01 00 01
        00 00 17 00 00
        """

    mybufferstream = new_io_bytes_from_string(mybuffer)
    res = await reader(mybufferstream)
    print(res)
    print("handshake type:", res.variant_type)
    print("version major :", res["server_version"]["major"].value)
    print("version minor :", res["server_version"]["minor"].value)
    print("random :", binascii.hexlify(res["random"].value))
    print("sessionID :", binascii.hexlify(res["session_id"].value))
    print("ciphersuite : ", binascii.hexlify(res["cipher_suite"].value))
    print("compression_method : ", binascii.hexlify(
        res["compression_method"].value))
    for ciphersuite in res["extensions"]:
        print("extension type :", ciphersuite.variant_type)
        print("extensions : ", ciphersuite.value)

    print(res.update_size())

    buf = io.BytesIO()

    print(res.write(buf))
    buf.seek(0)

    print(binascii.hexlify(buf.read(res.get_full_size())))
    print(binascii.hexlify(bytearray.fromhex(mybuffer)))

    mybuffer = """ 
        0B 00 02 BC 00 02 B9 00 02 B6 30 82 02 B2 30 82

        02 61 A0 03 02 01 02 02 0A 28 A2 90 E3 00 00 00

        D8 D1 42 30 08 06 06 2A 85 03 02 02 03 30 3A 31

        12 30 10 06 0A 09 92 26 89 93 F2 2C 64 01 19 16

        02 72 75 31 12 30 10 06 0A 09 92 26 89 93 F2 2C

        64 01 19 16 02 63 70 31 10 30 0E 06 03 55 04 03

        13 07 74 65 73 74 2D 63 61 30 1E 17 0D 31 37 31

        30 32 34 30 32 35 30 35 36 5A 17 0D 32 37 31 30

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
        """

    mybufferstream = new_io_bytes_from_string(mybuffer)
    res = await reader(mybufferstream)

    print(res.update_size())

    print(res)

    buf = io.BytesIO()

    print(res.write(buf))
    buf.seek(0)
    assert buf.read(res.get_full_size()) == bytearray.fromhex(mybuffer)


if __name__ == "__main__":
    asyncio.run(test_client_hello())
    asyncio.run(test_server_hello())
    asyncio.run(test_certificate_request())
    asyncio.run(test_server_hello_done())
    asyncio.run(test_client_key_exchange())
    asyncio.run(test_certificate_verify())
    asyncio.run(test_finished())
    asyncio.run(test_handshake())
