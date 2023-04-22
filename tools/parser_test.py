import unittest
from handshakeparser import HandshakeParser
from myparser import Parser
import io


class TestParser(unittest.TestCase):

    def check_basic(self, mypattern, mybuffer, parser=Parser()):
        mypytternstream = io.StringIO(mypattern)
        mybufferstream = io.BytesIO(mybuffer)

        reader = parser.parse(mypytternstream)

        res = reader(mybufferstream)

        self.assertEqual(res.to_bytes(), mybuffer)

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


if __name__ == '__main__':
    unittest.main()
