from mytoken import Token, TokenType, get_token_with_type

from error import *
from utils import *

import io
import binascii


class Result:
    def __init__(self, type, value, size, value_size, variant_type=0):
        self.type = type
        self.value = value
        self.size = size
        self.value_sie = value_size
        self.variant_type = variant_type

    def __str__(self) -> str:
        return "Result type: " + self.type + " value: " + str(self.value)

    def __repr__(self):
        return "Result type: " + self.type + " value: " + str(self.value)


def fbytes_reader(size: int):
    def reader(buffer: io.BytesIO):
        return Result('fbytes', get_bytes(buffer, size), size, size)
    return reader


def bytes_reader(size: int):
    def reader(buffer: io.BytesIO):
        value_size = get_int(buffer, size)
        return Result('bytes', get_bytes(buffer, value_size), size, value_size)
    return reader


def array_reader(size: int, type_reader):
    if type_reader is None:
        error_unknown_type()

    def reader(buffer: io.BytesIO):

        array_size = get_int(buffer, size)
        start = buffer.tell()
        res = []
        while start + array_size != buffer.tell():
            current = buffer.tell()
            res.append(type_reader(buffer))
            if start + array_size < buffer.tell():
                error_incorrect_length_array()
        return Result('array', res, size, array_size)

    return reader


def dict_reader(size: int, keys, type_readers):
    def reader(buffer: io.BytesIO):
        dict_size = get_int(buffer, size)
        start = buffer.tell()
        res = {}
        length = len(keys)
        for i in range(length):
            res[keys[i]] = type_readers[i](buffer)
        if start + dict_size != buffer.tell():
            error_incorrect_length_array()
        return Result('dict', res, size, dict_size)
    return reader


def fdict_reader(keys, type_readers):
    def reader(buffer: io.BytesIO):
        res = {}
        length = len(keys)
        for i in range(length):
            res[keys[i]] = type_readers[i](buffer)
        return Result('fdict', res, 0, 0)
    return reader


def variant_reader(size_length: int, type_readers):
    def reader(buffer: io.BytesIO):
        type = get_int(buffer, size_length)

        if not (type in type_readers):
            error_unknown_variant_type()
        res = type_readers[type](buffer)
        return Result('variant', res, size_length, 0, type)

    return reader


class Parser:

    def __init__(self):
        self.types = {}
        pass

    def parse(self,  patternstream: io.StringIO):
        token = get_token_with_type(patternstream, TokenType.name)

        return self.get_reader(token.value, patternstream)

    def get_reader(self, type: str, patternstream: io.StringIO):
        if type == 'bytes':
            return self.get_bytes_reader(patternstream)
        if type == 'fbytes':
            return self.get_fbytes_reader(patternstream)
        if type == 'array':
            return self.get_array_reader(patternstream)
        if type == 'dict':
            return self.get_dict_reader(patternstream)
        if type == 'fdict':
            return self.get_fdict_reader(patternstream)
        if type == 'variant':
            return self.get_variant_reader(patternstream)

        if type in self.types:
            return self.types[type]

        error_unknown_type

    def get_fbytes_reader(self,  patternstream: io.StringIO):
        get_token_with_type(patternstream, TokenType.left_bracket)
        token = get_token_with_type(patternstream, TokenType.const)
        get_token_with_type(patternstream, TokenType.right_bracket)

        return fbytes_reader(token.value)

    def get_bytes_reader(self,  patternstream: io.StringIO):
        get_token_with_type(patternstream, TokenType.left_bracket)
        token = get_token_with_type(patternstream, TokenType.const)
        get_token_with_type(patternstream, TokenType.right_bracket)

        return bytes_reader(token.value)

    def get_array_reader(self,  patternstream: io.StringIO):
        get_token_with_type(patternstream, TokenType.left_bracket)
        token = get_token_with_type(patternstream, TokenType.const)
        size = token.value
        get_token_with_type(patternstream, TokenType.comma)
        token = get_token_with_type(patternstream, TokenType.name)
        type_name = token.value
        type_reader = self.get_reader(type_name, patternstream)
        get_token_with_type(patternstream, TokenType.right_bracket)
        return array_reader(size, type_reader)

    def get_dict_reader(self,   patternstream: io.StringIO):
        get_token_with_type(patternstream, TokenType.left_bracket)
        keys = []
        type_readers = []
        token = get_token_with_type(patternstream, TokenType.const)
        size = token.value
        while (True):
            token = Token(patternstream)
            if token.type == TokenType.right_bracket:
                break
            if token.type != TokenType.comma:
                error_unexpected_token()
            token = get_token_with_type(patternstream, TokenType.name)
            keys.append(token.value)
            get_token_with_type(patternstream, TokenType.comma)
            token = get_token_with_type(patternstream, TokenType.name)
            type_readers.append(self.get_reader(token.value, patternstream))

        return dict_reader(size, keys, type_readers)

    def get_fdict_reader(self,   patternstream: io.StringIO):
        get_token_with_type(patternstream, TokenType.left_bracket)
        keys = []
        type_readers = []
        first = True
        while (True):
            if not first:
                token = Token(patternstream)
                if token.type == TokenType.right_bracket:
                    break
                if token.type != TokenType.comma:
                    error_unexpected_token()
            else:
                first = False
            token = get_token_with_type(patternstream, TokenType.name)
            keys.append(token.value)
            get_token_with_type(patternstream, TokenType.comma)
            token = get_token_with_type(patternstream, TokenType.name)
            type_readers.append(self.get_reader(token.value, patternstream))

        return fdict_reader(keys, type_readers)

    def get_variant_reader(self, patternstream: io.StringIO):
        get_token_with_type(patternstream, TokenType.left_bracket)
        type_readers = {}
        token = get_token_with_type(patternstream, TokenType.const)
        size = token.value
        while (True):
            token = Token(patternstream)
            if token.type == TokenType.right_bracket:
                break
            if token.type != TokenType.comma:
                error_unexpected_token()
            token = get_token_with_type(patternstream, TokenType.const)
            type = token.value
            get_token_with_type(patternstream, TokenType.comma)
            token = get_token_with_type(patternstream, TokenType.name)
            type_readers[type] = self.get_reader(token.value, patternstream)
        return variant_reader(size, type_readers)

    def remember(self, type, pattern):
        self.types[type] = self.parse(io.StringIO(pattern))

    def parse_type_name(self, type: str, buffer: io.BytesIO):
        return self.parse(io.StringIO(type), buffer)

    def parse_fbytes(self,  patternstream: io.StringIO, buffer: io.BytesIO):
        get_token_with_type(patternstream, TokenType.left_bracket)
        token = get_token_with_type(patternstream, TokenType.const)
        get_token_with_type(patternstream, TokenType.right_bracket)

        size = token.value
        return Result('fbytes', get_bytes(buffer, size), size)

    def parse_array(self,  patternstream: io.StringIO, buffer: io.BytesIO):
        get_token_with_type(patternstream, TokenType.left_bracket)
        token = get_token_with_type(patternstream, TokenType.const)
        size = token.value
        get_token_with_type(patternstream, TokenType.comma)
        token = get_token_with_type(patternstream, TokenType.name)
        type = token.value
        get_token_with_type(patternstream, TokenType.right_bracket)

        res = []
        start = buffer.tell()
        while size + start != buffer.tell:
            res.append(self.parse_type_name(type, buffer))
            if size + start < buffer.tell:
                error_incorrect_length_array()
        return Result('array', res, size)

    def parse_bytes(self,  patternstream: io.StringIO, buffer: io.BytesIO):
        get_token_with_type(patternstream, TokenType.left_bracket)
        token = get_token_with_type(patternstream, TokenType.const)
        get_token_with_type(patternstream, TokenType.right_bracket)

        size = token.value
        return Result('bytes', get_bytes(buffer, get_int(buffer, size)), size)


def test_bytes():
    parser = Parser()

    mypattern = "bytes(2))"
    mybuffer = bytearray.fromhex("00050001010102")

    mypytternstream = io.StringIO(mypattern)
    mybufferstream = io.BytesIO(mybuffer)

    reader = parser.parse(mypytternstream)

    print(reader(mybufferstream))


def test_fbytes():
    parser = Parser()

    mypattern = "fbytes(7)"
    mybuffer = bytearray.fromhex("00050001010102")

    mypytternstream = io.StringIO(mypattern)
    mybufferstream = io.BytesIO(mybuffer)

    reader = parser.parse(mypytternstream)

    print(reader(mybufferstream))


def test_array_of_bytes():
    parser = Parser()

    mypattern = "array(2, bytes(1))"
    mybuffer = bytearray.fromhex("00050001010102")

    mypytternstream = io.StringIO(mypattern)
    mybufferstream = io.BytesIO(mybuffer)

    reader = parser.parse(mypytternstream)

    print(reader(mybufferstream))


def test_array_of_fbytes():
    parser = Parser()

    mypattern = "array(2, fbytes(1))"
    mybuffer = bytearray.fromhex("00050001010102")

    mypytternstream = io.StringIO(mypattern)
    mybufferstream = io.BytesIO(mybuffer)

    reader = parser.parse(mypytternstream)

    print(reader(mybufferstream))


def test_dict():
    parser = Parser()

    parser.remember("a", "bytes(1)")
    parser.remember("b", "fbytes(1)")

    mypattern = "dict(2, a, b, b, a)"
    mybuffer = bytearray.fromhex("00050003010102")

    mypytternstream = io.StringIO(mypattern)
    mybufferstream = io.BytesIO(mybuffer)

    reader = parser.parse(mypytternstream)

    print(reader(mybufferstream))


def test_allias():
    parser = Parser()

    parser.remember("a", "bytes(1)")
    parser.remember("b", "fbytes(1)")

    mypattern = "a"
    mybuffer = bytearray.fromhex("03050003010102")

    mypytternstream = io.StringIO(mypattern)
    mybufferstream = io.BytesIO(mybuffer)

    reader = parser.parse(mypytternstream)

    print(reader(mybufferstream))

    mypattern = "b"
    mybuffer = bytearray.fromhex("03050003010102")

    mypytternstream = io.StringIO(mypattern)
    mybufferstream = io.BytesIO(mybuffer)

    reader = parser.parse(mypytternstream)

    print(reader(mybufferstream))


def test_variant():
    parser = Parser()

    parser.remember("a", "bytes(1)")
    parser.remember("b", "fbytes(1)")

    mypattern = "variant(1, 0, a, 1, b)"
    mybuffer = bytearray.fromhex("00030102030104")

    mypytternstream = io.StringIO(mypattern)
    mybufferstream = io.BytesIO(mybuffer)

    reader = parser.parse(mypytternstream)

    print(reader(mybufferstream))
    print(reader(mybufferstream))


def test_handshake():
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

    reader = parser.parse(mypytternstream)

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
    print("version major :", res.value.value["client_version"].value["major"].value)
    print("version minor :", res.value.value["client_version"].value["minor"].value)
    print("random :", binascii.hexlify( res.value.value["random"].value))
    print("sessionID :", binascii.hexlify( res.value.value["session_id"].value))
    for ciphersuite in  res.value.value["cipher_suites"].value:
        print("ciphersuite : ",  binascii.hexlify(ciphersuite.value))

    for ciphersuite in  res.value.value["compression_methods"].value:
        print("compression_method : ",  binascii.hexlify(ciphersuite.value))

    for ciphersuite in  res.value.value["extensions"].value:
        print("extension type :", ciphersuite.variant_type )
        print("extensions : ",  ciphersuite.value)

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
    print("version major :", res.value.value["server_version"].value["major"].value)
    print("version minor :", res.value.value["server_version"].value["minor"].value)
    print("random :", binascii.hexlify( res.value.value["random"].value))
    print("sessionID :", binascii.hexlify( res.value.value["session_id"].value))
    print("ciphersuite : ",  binascii.hexlify(res.value.value["cipher_suite"].value))
    print("compression_method : ",  binascii.hexlify(res.value.value["compression_method"].value))
    for ciphersuite in  res.value.value["extensions"].value:
        print("extension type :", ciphersuite.variant_type )
        print("extensions : ",  ciphersuite.value)


if __name__ == "__main__":
    test_array_of_bytes()
    test_array_of_fbytes()
    test_bytes()
    test_fbytes()
    test_dict()
    test_allias()
    test_variant()
    test_handshake()
