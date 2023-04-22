from myparser import Parser
import binascii
import io


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
    parser.remember("Signature_algorithms",
                    "array(2, SignatureAndHashAlgorithm)")
    parser.remember("Extended_master_secret", "bytes(2)")

    parser.remember("renegotiated_connection", "bytes(1)")

    parser.remember("RenegotiationInfo", "array(2, renegotiated_connection)")

    parser.remember(
        "Extension", "variant(2, 13, Signature_algorithms, 23, Extended_master_secret, 65281, RenegotiationInfo)")

    parser.remember("CliendHelloBody",
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

    parser.remember("Handshake", """variant(1,
                    0, fbytes(0),
                    1, CliendHelloBody,
                    2, ServerHelloBody
                    )""")

    mypattern = "Handshake"
    mypytternstream = io.StringIO(mypattern)

    return parser.parse(mypytternstream)


def test_handshake():
    reader = HandshakeParser()

    mybuffer = bytearray.fromhex(
        """
        01 00 00 40 03 03 93 3E A2 1E C3 80 2A 56 15 50
        EC 78 D6 ED 51 AC 24 39 D7 E7 49 C3 1B C3 A3 45
        61 65 88 96 84 CA 00 00 04 FF 88 FF 89 01 00 00
        13 00 0D 00 06 00 04 EE EE EF EF FF 01 00 01 00
        00 17 00 00
        """)
    mybufferstream = io.BytesIO(mybuffer)
    res = reader(mybufferstream)
    print(res)
    print("handshake type:", res.variant_type)
    print("version major :", res["client_version"]["major"].value)
    print("version minor :", res["client_version"]["minor"].value)
    print("random :", binascii.hexlify(res["random"].value))
    print("sessionID :", binascii.hexlify(res["session_id"].value))
    for ciphersuite in res["cipher_suites"]:
        print("ciphersuite : ",  binascii.hexlify(ciphersuite.value))

    print(res["cipher_suites"][0].value)

    for ciphersuite in res["compression_methods"]:
        print("compression_method : ",  binascii.hexlify(ciphersuite.value))

    for ciphersuite in res["extensions"]:
        print("extension type :", ciphersuite.variant_type)
        print("extensions : ",  ciphersuite.value)

    print(res.update_size())

    buf = io.BytesIO()

    print(res.write(buf))
    buf.seek(0)
    print(binascii.hexlify(buf.read(res.get_full_size())))
    print(binascii.hexlify(mybuffer))

    mybuffer = bytearray.fromhex(
        """
        02 00 00 41 03 03 93 3E A2 1E 49 C3 1B C3 A3 45
        61 65 88 96 84 CA A5 57 6C E7 92 4A 24 F5 81 13
        80 8D BD 9E F8 56 10 C3 80 2A 56 15 50 EC 78 D6
        ED 51 AC 24 39 D7 E7 FF 88 00 00 09 FF 01 00 01
        00 00 17 00 00
        """)

    mybufferstream = io.BytesIO(mybuffer)
    res = reader(mybufferstream)
    print(res)
    print("handshake type:", res.variant_type)
    print("version major :", res["server_version"]["major"].value)
    print("version minor :", res["server_version"]["minor"].value)
    print("random :", binascii.hexlify(res["random"].value))
    print("sessionID :", binascii.hexlify(res["session_id"].value))
    print("ciphersuite : ",  binascii.hexlify(res["cipher_suite"].value))
    print("compression_method : ",  binascii.hexlify(
        res["compression_method"].value))
    for ciphersuite in res["extensions"]:
        print("extension type :", ciphersuite.variant_type)
        print("extensions : ",  ciphersuite.value)

    print(res.update_size())

    buf = io.BytesIO()

    print(res.write(buf))
    buf.seek(0)

    print(binascii.hexlify(buf.read(res.get_full_size())))
    print(binascii.hexlify(mybuffer))


if __name__ == "__main__":
    test_handshake()