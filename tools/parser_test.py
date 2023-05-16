import binascii
import unittest
from handshakeparser import HandshakeParser
from myparser import Parser
from ASN import parse_ASN
from utils import *
import io

from unittest import IsolatedAsyncioTestCase

from tools.asyncbyte import abyte


class TestParser(IsolatedAsyncioTestCase):

    async def check_basic(self, mypattern, mybuffer_hex, parser=Parser()):
        mypytternstream = io.StringIO(mypattern)
        mybufferstream = new_io_bytes_from_string(mybuffer_hex)

        reader = parser.parse(mypytternstream)

        res = await reader(mybufferstream)

        self.assertEqual(res.to_bytes(), bytearray.fromhex(mybuffer_hex))

    @staticmethod
    def check_result_output(buffer, res):
        buf = io.BytesIO()
        res.write(buf)
        buf.seek(0)
        out = buf.read(res.get_full_size())
        assert out == buffer

    async def test_bytes(self):
        mypattern = "bytes(2)"
        mybuffer_hex = "00050001010102"

        await self.check_basic(mypattern, mybuffer_hex)

    async def test_fbytes(self):
        mypattern = "fbytes(7)"
        mybuffer_hex = "00050001010102"

        await self.check_basic(mypattern, mybuffer_hex)

    async def test_array_of_bytes(self):
        mypattern = "array(2, bytes(1))"
        mybuffer_hex = "00050001010102"

        await self.check_basic(mypattern, mybuffer_hex)

    async def test_array_of_fbytes(self):
        mypattern = "array(2, fbytes(1))"
        mybuffer_hex = "00050001010102"

        await self.check_basic(mypattern, mybuffer_hex)

    async def test_dict(self):
        parser = Parser()

        parser.remember("a", "bytes(1)")
        parser.remember("b", "fbytes(1)")

        mypattern = "dict(2, a, b, b, a)"
        mybuffer_hex = "00050003010102"

        await self.check_basic(mypattern, mybuffer_hex, parser)

    async def test_allias(self):
        parser = Parser()

        parser.remember("a", "bytes(1)")
        parser.remember("b", "fbytes(1)")

        mypattern = "a"
        mybuffer_hex = "03050003"

        await self.check_basic(mypattern, mybuffer_hex, parser)

    async def test_variant(self):
        parser = Parser()

        parser.remember("a", "bytes(1)")
        parser.remember("b", "fbytes(1)")

        mypattern = "variant(1, 0, a, 1, b)"
        mybuffer_hex = "0003010203"

        await self.check_basic(mypattern, mybuffer_hex, parser)
        mybuffer_hex = "0102"
        await self.check_basic(mypattern, mybuffer_hex, parser)

    async def test_handshake(self):
        reader = HandshakeParser()

        mybuffer_hex = """
            01 00 00 40 03 03 93 3E A2 1E C3 80 2A 56 15 50
            EC 78 D6 ED 51 AC 24 39 D7 E7 49 C3 1B C3 A3 45
            61 65 88 96 84 CA 00 00 04 FF 88 FF 89 01 00 00
            13 00 0D 00 06 00 04 EE EE EF EF FF 01 00 01 00
            00 17 00 00
            """

        mybuffer = bytearray.fromhex(mybuffer_hex)

        mybufferstream = new_io_bytes_from_string(mybuffer_hex)

        self.assertEqual((await reader(mybufferstream)).to_bytes(), mybuffer)

        mybuffer_hex = """
                    02 00 00 41 03 03 93 3E A2 1E 49 C3 1B C3 A3 45
                    61 65 88 96 84 CA A5 57 6C E7 92 4A 24 F5 81 13
                    80 8D BD 9E F8 56 10 C3 80 2A 56 15 50 EC 78 D6
                    ED 51 AC 24 39 D7 E7 FF 88 00 00 09 FF 01 00 01
                    00 00 17 00 00
                    """
        mybuffer = bytearray.fromhex(mybuffer_hex)

        mybufferstream = new_io_bytes_from_string(mybuffer_hex)

        self.assertEqual((await reader(mybufferstream)).to_bytes(), mybuffer)

        mybuffer_hex = """ 
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

        mybuffer = bytearray.fromhex(mybuffer_hex)

        mybufferstream = new_io_bytes_from_string(mybuffer_hex)

        self.assertEqual((await reader(mybufferstream)).to_bytes(), mybuffer)

    async def test_ASN_bool(self):
        pass

    async def test_ASN_INT(self):
        mybufferstream = new_io_bytes_from_string("02 01 02")

        res = await parse_ASN(mybufferstream)

        expected = ASN_INT(2)
        compare_result(res, expected)

    async def test_ASN_BITE(self):
        mybufferstream = new_io_bytes_from_string("""03 43 00 04 40
                    0bd86fe5d8db89668f789b4e1dba8585
                    c5508b45ec5b59d8906ddb70e2492b7f
                    da77ff871a10fbdf2766d293c5d164af
                    bb3c7b973a41c885d11d70d689b4f126""")

        res = await parse_ASN(mybufferstream)

        expected = ASN_BIT("""00 04 40
                    0bd86fe5d8db89668f789b4e1dba8585
                    c5508b45ec5b59d8906ddb70e2492b7f
                    da77ff871a10fbdf2766d293c5d164af
                    bb3c7b973a41c885d11d70d689b4f126""")

        compare_result(res, expected)

    async def test_ASN_OCTET(self):
        mybufferstream = new_io_bytes_from_string("""04 40
                    0bd86fe5d8db89668f789b4e1dba8585
                    c5508b45ec5b59d8906ddb70e2492b7f
                    da77ff871a10fbdf2766d293c5d164af
                    bb3c7b973a41c885d11d70d689b4f126""")

        res = await parse_ASN(mybufferstream)

        expected = ASN_OCT("""
                    0bd86fe5d8db89668f789b4e1dba8585
                    c5508b45ec5b59d8906ddb70e2492b7f
                    da77ff871a10fbdf2766d293c5d164af
                    bb3c7b973a41c885d11d70d689b4f126""")
        compare_result(res, expected)

    async def test_ASN_OID(self):
        mybufferstream = new_io_bytes_from_string(
            """06 08 2a 85 03 07 01 01 03 02""")

        res = await parse_ASN(mybufferstream)

        expected = ASN_OID("[1.2.643.7.1.1.3.2]")
        compare_result(res, expected)

    async def test_ASN_PRINTABLE(self):
        mybufferstream = new_io_bytes_from_string(
            """13 07 45 78 61 6d 70 6c 65""")

        res = await parse_ASN(mybufferstream)

        expected = ASN_PRI("Example")
        compare_result(res, expected)

    async def test_ASN_TIME(self):
        mybufferstream = new_io_bytes_from_string(
            """17 0d 3031303130313030303030305a
            18 0f 32303530313233313030303030305a""")

        res = await parse_ASN(mybufferstream)

        expected = ASN_UTC("010101000000Z")
        compare_result(res, expected)

        res = await parse_ASN(mybufferstream)

        expected = ASN_GT("20501231000000Z")
        compare_result(res, expected)

    async def test_ASN_CS(self):
        mybufferstream = new_io_bytes_from_string("a003020102")

        res = await parse_ASN(mybufferstream)

        expected = ASN_CST(0, ASN_INT(2))
        compare_result(res, expected)

    async def test_ASN_SEQ(self):
        mybufferstream = new_io_bytes_from_string(
            """30 03 02 01 02
        """)

        mybuffer = bytearray.fromhex("""30 03 02 01 02
        """)

        res = await parse_ASN(mybufferstream)

        expected = ASNSEQ([ASN_INT(2)])
        compare_result(res, expected)
        self.check_result_output(mybuffer, res)

        mybuffer = bytearray.fromhex("""30 12 
            31 10
                30 0e
                    06 03 55 04 03
                    13 07 45 78 61 6d 70 6c 65
        """)

        mybufferstream = abyte(io.BytesIO(mybuffer))

        res = await parse_ASN(mybufferstream)

        expected = ASNSEQ([ASNSEQ([ASNSEQ([ASN_OID("[2.5.4.3]"),
                                           ASN_PRI("Example")])])])
        compare_result(res, expected)

        self.check_result_output(mybuffer, res)

    async def test_ASN_Cert_Example_1(self):
        mybuffer = bytearray.fromhex(
            """3082012d3081dba00302010202010a300a06082a8503070101030230123110300e060355040313074578616d706c653020170d3031303130313030303030305a180f32303530313233313030303030305a30123110300e060355040313074578616d706c653066301f06082a85030701010101301306072a85030202230006082a8503070101020203430004400bd86fe5d8db89668f789b4e1dba8585c5508b45ec5b59d8906ddb70e2492b7fda77ff871a10fbdf2766d293c5d164afbb3c7b973a41c885d11d70d689b4f126a3133011300f0603551d130101ff040530030101ff300a06082a850307010103020341004d53f012fe081776507d4d9bb81f00efdb4eefd4ab83bac4bacf735173cfa81c41aa28d2f1ab148280cd9ed56feda41974053554a42767b83ad043fd39dc0493"""
        )

        mybufferstream = abyte(io.BytesIO(mybuffer))

        res = await parse_ASN(mybufferstream)

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
        compare_result(res, expected)

        self.check_result_output(mybuffer, res)

    async def test_ASN_Cert_Example_2(self):
        mybuffer = bytearray.fromhex(
            """308201253081d3a00302010202010a300a06082a8503070101030230123110300e060355040313074578616d706c653020170d3031303130313030303030305a180f32303530313233313030303030305a30123110300e060355040313074578616d706c65305e301706082a85030701010101300b06092a85030701020101010343000440742795d4bee884ddf2850fec03ea3faf1844e01d9da60b645093a55e26dfc39978f596cf4d4d0c6cf1d18943d94493d16b9ec0a16d512d2e127cc4691a6318e2a3133011300f0603551d130101ff040530030101ff300a06082a85030701010302034100140b4da9124b09cb0d5ce928ee874273a310129492ec0e29369e3b791248578c1d0e1da5be347c6f1b5256c7aeac200ad64ac77a6f5b3a0e097318e7ae6ee769"""
        )

        mybufferstream = abyte(io.BytesIO(mybuffer))

        res = await parse_ASN(mybufferstream)

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
                            ASN_OID("[1.2.643.7.1.2.1.1.1]"),

                        ])
                    ]),
                    ASN_BIT("""00 04 40
                    742795D4BEE884DDF2850FEC03EA3FAF
                    1844E01D9DA60B645093A55E26DFC399
                    78F596CF4D4D0C6CF1D18943D94493D1
                    6B9EC0A16D512D2E127CC4691A6318E2""")
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
            140B4DA9124B09CB0D5CE928EE874273
            A310129492EC0E29369E3B791248578C
            1D0E1DA5BE347C6F1B5256C7AEAC200A
            D64AC77A6F5B3A0E097318E7AE6EE769""")

        ])
        compare_result(res, expected)

        self.check_result_output(mybuffer, res)

    async def test_ASN_Cert_CryptoPro(self):
        val = """3082055c30820509a003020102021102e648070170afc89d4905fa0fb3354006300a06082a850307010103023081963115301306052a85036404120a373731373130373939313118301606052a85036401120d31303337373030303835343434310b3009060355040613025255310f300d06035504080c064d6f73636f77310f300d06035504070c064d6f73636f7731193017060355040a0c104c4c43202243727970746f2d50726f223119301706035504030c1043727970746f50726f20544c53204341301e170d3232313231393135343833365a170d3234303331393135343833365a3081a131253023060355040a0c1cd09ed09ed09e2022d09ad0a0d098d09fd0a2d09e2dd09fd0a0d09e223115301306035504070c0cd09cd0bed181d0bad0b2d0b03119301706035504080c10d0b32e20d09cd0bed181d0bad0b2d0b0310b30090603550406130252553139303706035504030c30d092d0b5d0b12dd181d0b5d180d0b2d0b5d18020d09ed09ed09e2022d09ad0a0d098d09fd0a2d09e2dd09fd0a0d09e223066301f06082a85030701010101301306072a85030202240006082a850307010102020343000440162e613c1fef72b1f5004e2168c41b3166488c88463b50f3dd08bb4e111f2037f5462b00a6c2818be4413a2745486787247e5c0a001375f738f85e368a902a9da382031c30820318300e0603551d0f0101ff040403020430301d0603551d0e04160414e8b3e4480e85aaff46c28ecddea7b0895efe673e303506092b060104018237150704283026061e2a850302023201048694b432859df95184f98e4584b5c57f83805481b64402010102010030130603551d25040c300a06082b060105050703013081a206082b06010505070101048195308192303406082b060105050730028628687474703a2f2f6364702e63727970746f70726f2e72752f72612f6169612f746c7363612e703762305a06082b06010505073002864e687474703a2f2f746c736361323031322e63727970746f70726f2e72752f6169612f643264643064306362326635306462663736313964356137356436653033383735333332353730342e63727430610603551d11045a3058820e2a2e63727970746f70726f2e7275820c63727970746f70726f2e7275820f2a2e63727970746f2d70726f2e7275820d63727970746f2d70726f2e72758218786e2d2d683161646e6164626465702e786e2d2d703161693081b10603551d1f0481a93081a6304ea04ca04a8648687474703a2f2f6364702e63727970746f70726f2e72752f6364702f643264643064306362326635306462663736313964356137356436653033383735333332353730342e63726c3054a052a050864e687474703a2f2f746c736361323031322e63727970746f70726f2e72752f6364702f643264643064306362326635306462663736313964356137356436653033383735333332353730342e63726c3081de0603551d230481d63081d38014d2dd0d0cb2f50dbf7619d5a75d6e038753325704a181a7a481a43081a13118301606052a85036401120d31303337373030303835343434311a301806082a85030381030101120c303037373137313037393931310b3009060355040613025255310f300d06035504080c064d6f73636f77310f300d06035504070c064d6f73636f7731193017060355040a0c104c4c43202243727970746f2d50726f22311f301d06035504030c1643727970746f50726f20474f535420526f6f742043418211011265e80070afe39e49bbb74606f46829300a06082a850307010103020341002bb9a6e6a04081f9ea0c31e70201b3010e5552d4e961ca6897ac80a829a67aa6eebd7eb67bdbeeee0fa4cea9ca9a980acaa4ae4629fec9c742fd3f3e989f3436"""

        mybuffer = bytearray.fromhex(
            val
        )

        mybufferstream = abyte(io.BytesIO(mybuffer))

        res = await parse_ASN(mybufferstream)

        assert mybuffer == res.to_bytes()



    async def test_ASN_Cert_Example_3(self):
        mybuffer = bytearray.fromhex(
            """308201aa30820116a00302010202010b300a06082a8503070101030330123110300e060355040313074578616d706c653020170d3031303130313030303030305a180f32303530313233313030303030305a30123110300e060355040313074578616d706c653081a0301706082a85030701010102300b06092a850307010201020003818400048180e1ef30d52c6133ddd99d1d5c41455cf7df4d8b4c925bbc69af1433d15658515add2146850c325c5b81c133be655aa8c4d440e7b98a8d59487b0c7696bcc55d11ecbe7736a9ec357ff2fd39931f4e114cb8cda359270ac7f0e7ff43d9419419ea61fd2ab77f5d9f63523d3b50a04f63e2a0cf51b7c13adc21560f0bd40cc9c737a3133011300f0603551d130101ff040530030101ff300a06082a8503070101030303818100415703d892f1a5f3f68c4353189a7ee207b80b5631ef9d49529a4d6b542c2cfa15aa2eacf11f470fde7d954856903c35fd8f955ef300d95c77534a724a0eee702f86fa60a081091a23dd795e1e3c689ee512a3c82ee0dcc2643c78eea8fcacd35492558486b20f1c9ec197c90699850260c93bcbcd9c5c3317e19344e173ae36"""
        )

        mybufferstream = abyte(io.BytesIO(mybuffer))

        res = await parse_ASN(mybufferstream)

        expected = ASNSEQ([
            ASNSEQ([
                ASN_CST(0, ASN_INT(2)),
                ASN_INT(11),
                ASNSEQ([
                    ASN_OID("[1.2.643.7.1.1.3.3]")
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
                        ASN_OID("[1.2.643.7.1.1.1.2]"),
                        ASNSEQ([
                            ASN_OID("[1.2.643.7.1.2.1.2.0]"),

                        ])
                    ]),
                    ASN_BIT("""00 04 81 80
                    E1EF30D52C6133DDD99D1D5C41455CF7
                    DF4D8B4C925BBC69AF1433D15658515A
                    DD2146850C325C5B81C133BE655AA8C4
                    D440E7B98A8D59487B0C7696BCC55D11
                    ECBE7736A9EC357FF2FD39931F4E114C
                    B8CDA359270AC7F0E7FF43D9419419EA
                    61FD2AB77F5D9F63523D3B50A04F63E2
                    A0CF51B7C13ADC21560F0BD40CC9C737""")
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
                ASN_OID("[1.2.643.7.1.1.3.3]")
            ]),
            ASN_BIT("""00
            415703D892F1A5F3F68C4353189A7EE2
            07B80B5631EF9D49529A4D6B542C2CFA
            15AA2EACF11F470FDE7D954856903C35
            FD8F955EF300D95C77534A724A0EEE70
            2F86FA60A081091A23DD795E1E3C689E
            E512A3C82EE0DCC2643C78EEA8FCACD3
            5492558486B20F1C9EC197C906998502
            60C93BCBCD9C5C3317E19344E173AE36
            """)
        ])
        compare_result(res, expected)

        self.check_result_output(mybuffer, res)

    async def test_key_exchange(self):
        mybuffer = bytearray.fromhex(
            """
            10 00 00 E2 30 81 DF 04 30 25 0D 1B 67 A2 70 AB
            04 D3 F6 54 18 E1 D3 80 B4 CB 94 5F 0A 3D CA 51
            50 0C F3 A1 BE F3 7F 76 C0 73 41 A9 83 9C CF 6C
            BA 71 89 DA 61 EB 67 17 6C 30 81 AA 30 21 06 08
            2A 85 03 07 01 01 01 02 30 15 06 09 2A 85 03 07
            01 02 01 02 03 06 08 2A 85 03 07 01 01 02 03 03
            81 84 00 04 81 80 C6 5B D7 05 B6 86 01 98 BA D4
            A7 0E B9 37 B6 B4 80 84 E2 60 AD F7 B1 07 4A 89
            18 28 62 C5 BF FE 64 86 28 35 41 33 0B 15 0F E4
            8A 73 7C B3 E5 BB 04 3E 4A 11 34 03 5A 6D 47 9B
            18 93 51 BE 41 C9 BE 9A 7E 2A FC 24 62 76 FE 4E
            23 56 84 52 93 B0 31 78 E2 EC 00 3C A8 A8 14 32
            4F 16 35 0B C0 AB 53 41 87 DE 86 C7 6B E2 9A 94
            0A 8D B2 AD 71 64 6A A0 C9 52 FD F4 11 20 65 48
            81 3E B9 F7 54 A1
            """
        )

        mybufferstream = abyte(io.BytesIO(mybuffer))

        reader = HandshakeParser()

        res = await reader(mybufferstream)

        print(res)

    async def test_key_exchange_2(self):
        mybuffer = bytearray.fromhex(
            """
            10 00 00 95 30 81 92 04 28 D7 F0 F0 42 23 67 86
            7B 25 FA 42 33 A9 54 F5 8B DE 92 E9 C9 BB FB 88
            16 C9 9F 15 E6 39 87 22 A0 B2 B7 BF E8 49 3E 9A
            5C 30 66 30 1F 06 08 2A 85 03 07 01 01 01 01 30
            13 06 07 2A 85 03 02 02 23 01 06 08 2A 85 03 07
            01 01 02 02 03 43 00 04 40 93 07 E0 98 C1 71 88
            F1 F1 47 7F EF B8 7F AE F1 BB CD 95 67 3B 1B 8F
            97 03 A2 62 D2 63 6D F3 A8 87 F8 14 1F EA C2 5A
            17 CC B5 96 04 61 ED 16 B0 F8 B1 BE 93 59 43 95
            A1 0E 64 85 44 6B 5D CA 34
            """
        )

        mybufferstream = abyte(io.BytesIO(mybuffer))

        reader = HandshakeParser()

        res = await reader(mybufferstream)

        print(res)


if __name__ == '__main__':
    unittest.main()
