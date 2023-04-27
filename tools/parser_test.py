import unittest
from handshakeparser import HandshakeParser
from myparser import Parser
from ASN import parse_ASN
from utils import *
import io


class TestParser(unittest.TestCase):

    def check_basic(self, mypattern, mybuffer, parser=Parser()):
        mypytternstream = io.StringIO(mypattern)
        mybufferstream = io.BytesIO(mybuffer)

        reader = parser.parse(mypytternstream)

        res = reader(mybufferstream)

        self.assertEqual(res.to_bytes(), mybuffer)

    def check_result_output(self, buffer, res):
        buf = io.BytesIO()
        res.write(buf)
        buf.seek(0)
        out = buf.read(res.get_full_size())
        assert out == buffer

    def test_bytes(self):

        mypattern = "bytes(2)"
        mybuffer = bytearray.fromhex("00050001010102")

        self.check_basic(mypattern, mybuffer)

    def test_fbytes(self):

        mypattern = "fbytes(7)"
        mybuffer = bytearray.fromhex("00050001010102")

        self.check_basic(mypattern, mybuffer)

    def test_array_of_bytes(self):

        mypattern = "array(2, bytes(1))"
        mybuffer = bytearray.fromhex("00050001010102")

        self.check_basic(mypattern, mybuffer)

    def test_array_of_fbytes(self):

        mypattern = "array(2, fbytes(1))"
        mybuffer = bytearray.fromhex("00050001010102")

        self.check_basic(mypattern, mybuffer)

    def test_dict(self):
        parser = Parser()

        parser.remember("a", "bytes(1)")
        parser.remember("b", "fbytes(1)")

        mypattern = "dict(2, a, b, b, a)"
        mybuffer = bytearray.fromhex("00050003010102")

        self.check_basic(mypattern, mybuffer, parser)

    def test_allias(self):
        parser = Parser()

        parser.remember("a", "bytes(1)")
        parser.remember("b", "fbytes(1)")

        mypattern = "a"
        mybuffer = bytearray.fromhex("03050003")

        self.check_basic(mypattern, mybuffer, parser)

    def test_variant(self):
        parser = Parser()

        parser.remember("a", "bytes(1)")
        parser.remember("b", "fbytes(1)")

        mypattern = "variant(1, 0, a, 1, b)"
        mybuffer = bytearray.fromhex("0003010203")

        self.check_basic(mypattern, mybuffer, parser)
        mybuffer = bytearray.fromhex("0102")
        self.check_basic(mypattern, mybuffer, parser)

    def test_handshake(self):
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

        self.assertEqual(reader(mybufferstream).to_bytes(), mybuffer)

        mybuffer = bytearray.fromhex(
            """
            02 00 00 41 03 03 93 3E A2 1E 49 C3 1B C3 A3 45
            61 65 88 96 84 CA A5 57 6C E7 92 4A 24 F5 81 13
            80 8D BD 9E F8 56 10 C3 80 2A 56 15 50 EC 78 D6
            ED 51 AC 24 39 D7 E7 FF 88 00 00 09 FF 01 00 01
            00 00 17 00 00
            """)

        mybufferstream = io.BytesIO(mybuffer)

        self.assertEqual(reader(mybufferstream).to_bytes(), mybuffer)

        mybuffer = bytearray.fromhex(
            """ 
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
        )

        mybufferstream = io.BytesIO(mybuffer)

        self.assertEqual(reader(mybufferstream).to_bytes(), mybuffer)

    def test_ASN_bool(self):
        pass

    def test_ASN_INT(self):
        mybufferstream = new_io_bytes_from_string("02 01 02")

        res = parse_ASN(mybufferstream)

        expected = ASN_INT(2)
        compare_result(res, expected)

    def test_ASN_BITE(self):
        mybufferstream = new_io_bytes_from_string("""03 43 00 04 40
                    0bd86fe5d8db89668f789b4e1dba8585
                    c5508b45ec5b59d8906ddb70e2492b7f
                    da77ff871a10fbdf2766d293c5d164af
                    bb3c7b973a41c885d11d70d689b4f126""")

        res = parse_ASN(mybufferstream)

        expected = ASN_BIT("""00 04 40
                    0bd86fe5d8db89668f789b4e1dba8585
                    c5508b45ec5b59d8906ddb70e2492b7f
                    da77ff871a10fbdf2766d293c5d164af
                    bb3c7b973a41c885d11d70d689b4f126""")

        compare_result(res, expected)

    def test_ASN_OCTET(self):
        mybufferstream = new_io_bytes_from_string("""04 40
                    0bd86fe5d8db89668f789b4e1dba8585
                    c5508b45ec5b59d8906ddb70e2492b7f
                    da77ff871a10fbdf2766d293c5d164af
                    bb3c7b973a41c885d11d70d689b4f126""")

        res = parse_ASN(mybufferstream)

        expected = ASN_OCT("""
                    0bd86fe5d8db89668f789b4e1dba8585
                    c5508b45ec5b59d8906ddb70e2492b7f
                    da77ff871a10fbdf2766d293c5d164af
                    bb3c7b973a41c885d11d70d689b4f126""")
        compare_result(res, expected)

    def test_ASN_OID(self):
        mybufferstream = new_io_bytes_from_string(
            """06 08 2a 85 03 07 01 01 03 02""")

        res = parse_ASN(mybufferstream)

        expected = ASN_OID("[1.2.643.7.1.1.3.2]")
        compare_result(res, expected)

    def test_ASN_PRINTABLE(self):
        mybufferstream = new_io_bytes_from_string(
            """13 07 45 78 61 6d 70 6c 65""")

        res = parse_ASN(mybufferstream)

        expected = ASN_PRI("Example")
        compare_result(res, expected)

    def test_ASN_TIME(self):
        mybufferstream = new_io_bytes_from_string(
            """17 0d 3031303130313030303030305a
            18 0f 32303530313233313030303030305a""")

        res = parse_ASN(mybufferstream)

        expected = ASN_UTC("010101000000Z")
        compare_result(res, expected)

        res = parse_ASN(mybufferstream)

        expected = ASN_GT("20501231000000Z")
        compare_result(res, expected)

    def test_ASN_CS(self):
        mybufferstream = new_io_bytes_from_string("a003020102")

        res = parse_ASN(mybufferstream)

        expected = ASN_CST(0, ASN_INT(2))
        compare_result(res, expected)

    def test_ASN_SEQ(self):

        mybufferstream = new_io_bytes_from_string(
            """30 03 02 01 02
        """)

        mybuffer = bytearray.fromhex("""30 03 02 01 02
        """)

        mybufferstream = io.BytesIO(mybuffer)

        res = parse_ASN(mybufferstream)

        expected = ASNSEQ([ASN_INT(2)])
        compare_result(res, expected)
        self.check_result_output(mybuffer, res)

        mybuffer = bytearray.fromhex("""30 12 
            31 10
                30 0e
                    06 03 55 04 03
                    13 07 45 78 61 6d 70 6c 65
        """)

        mybufferstream = io.BytesIO(mybuffer)

        res = parse_ASN(mybufferstream)

        expected = ASNSEQ([ASNSEQ([ASNSEQ([ASN_OID("[2.5.4.3]"),
                                           ASN_PRI("Example")])])])
        compare_result(res, expected)

        self.check_result_output(mybuffer, res)

    def test_ASN_Cert(self):

        mybuffer = bytearray.fromhex(
            """3082012d3081dba00302010202010a300a06082a8503070101030230123110300e060355040313074578616d706c653020170d3031303130313030303030305a180f32303530313233313030303030305a30123110300e060355040313074578616d706c653066301f06082a85030701010101301306072a85030202230006082a8503070101020203430004400bd86fe5d8db89668f789b4e1dba8585c5508b45ec5b59d8906ddb70e2492b7fda77ff871a10fbdf2766d293c5d164afbb3c7b973a41c885d11d70d689b4f126a3133011300f0603551d130101ff040530030101ff300a06082a850307010103020341004d53f012fe081776507d4d9bb81f00efdb4eefd4ab83bac4bacf735173cfa81c41aa28d2f1ab148280cd9ed56feda41974053554a42767b83ad043fd39dc0493"""
        )

        mybufferstream = io.BytesIO(mybuffer)

        res = parse_ASN(mybufferstream)

        expected = ASNSEQ([
            ASNSEQ([
                ASN_CST(0, ASN_INT(2)),
                ASN_INT(10),
                ASNSEQ([
                    ASN_OID("[1.2.643.7.1.1.3.2]")
                ]),
                ASNSEQ([
                    ASNSEQ([
                        ASNSEQ([
                            ASN_OID("[2.5.4.3]"),
                            ASN_PRI("Example")
                        ])
                    ])
                ]),
                ASNSEQ([
                    ASN_UTC("010101000000Z"),
                    ASN_GT("20501231000000Z")
                ]),
                ASNSEQ([
                    ASNSEQ([
                        ASNSEQ([
                            ASN_OID("[2.5.4.3]"),
                            ASN_PRI("Example")
                        ])
                    ])
                ]),
                ASNSEQ([
                    ASNSEQ([
                        ASN_OID("[1.2.643.7.1.1.1.1]"),
                        ASNSEQ([
                            ASN_OID("[1.2.643.2.2.35.0]"),
                            ASN_OID("[1.2.643.7.1.1.2.2]")
                        ])
                    ]),
                    ASN_BIT("""00 04 40
                    0bd86fe5d8db89668f789b4e1dba8585
                    c5508b45ec5b59d8906ddb70e2492b7f
                    da77ff871a10fbdf2766d293c5d164af
                    bb3c7b973a41c885d11d70d689b4f126""")
                ]),
                ASN_CST(3,
                        ASNSEQ([
                            ASNSEQ([
                                ASN_OID("[2.5.29.19]"),
                                ASN_BOOL(True),
                                ASN_OCT("30030101ff")
                            ])
                        ])
                        )
            ]),
            ASNSEQ([
                ASN_OID("[1.2.643.7.1.1.3.2]")
            ]),
            ASN_BIT("""00
            4d53f012fe081776507d4d9bb81f00ef
            db4eefd4ab83bac4bacf735173cfa81c
            41aa28d2f1ab148280cd9ed56feda419
            74053554a42767b83ad043fd39dc0493""")

        ])
        print(res)
        compare_result(res, expected)

        self.check_result_output(mybuffer, res)


if __name__ == '__main__':
    unittest.main()
