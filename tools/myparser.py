from mytoken import Token, TokenType, get_token_with_type

from collections import OrderedDict

from error import *
from utils import *
from result import Result

from ASN import parse_ASN

import io
import binascii


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
            res.append(type_reader(buffer))
            if start + array_size < buffer.tell():
                error_incorrect_length_array()
        return Result('array', res, size, array_size)

    return reader


def dict_reader(size: int, keys, type_readers):
    def reader(buffer: io.BytesIO):
        dict_size = get_int(buffer, size)
        start = buffer.tell()
        res = OrderedDict()
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
        if type == 'ASN':
            return parse_ASN

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

    mypattern = "bytes(2)"
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

def test_ASN():
    parser = Parser()
    mypattern = "ASN"
    mypytternstream = io.StringIO(mypattern)

    mybufferstream = new_io_bytes_from_string(
        """3082012d3081dba00302010202010a300a06082a8503070101030230123110300e060355040313074578616d706c653020170d3031303130313030303030305a180f32303530313233313030303030305a30123110300e060355040313074578616d706c653066301f06082a85030701010101301306072a85030202230006082a8503070101020203430004400bd86fe5d8db89668f789b4e1dba8585c5508b45ec5b59d8906ddb70e2492b7fda77ff871a10fbdf2766d293c5d164afbb3c7b973a41c885d11d70d689b4f126a3133011300f0603551d130101ff040530030101ff300a06082a850307010103020341004d53f012fe081776507d4d9bb81f00efdb4eefd4ab83bac4bacf735173cfa81c41aa28d2f1ab148280cd9ed56feda41974053554a42767b83ad043fd39dc0493"""
    )

    reader = parser.parse(mypytternstream)

    print(reader(mybufferstream))
    

if __name__ == "__main__":
    test_array_of_bytes()
    test_array_of_fbytes()
    test_bytes()
    test_fbytes()
    test_dict()
    test_allias()
    test_variant()
    test_ASN()

