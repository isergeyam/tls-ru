from mytoken import Token, TokenType, get_token_with_type

from collections import OrderedDict

from error import *
from utils import *

import io
import binascii


class Result:
    def __init__(self, type, value, size, value_size, variant_type=0):
        self.type = type
        self.value = value
        self.size = size
        self.value_size = value_size
        self.variant_type = variant_type

    def __str__(self) -> str:
        return "Result type: " + self.type + " value: " + str(self.value)

    def __repr__(self):
        return "Result type: " + self.type + " value: " + str(self.value)

    def __getitem__(self, key):
        return self.value[key]

    def update_size(self):
        if self.type == "fbytes":
            self.value_size = len(self.value)
            return self.value_size
        if self.type == "bytes":
            self.value_size = len(self.value)
            return self.value_size + self.size
        if self.type == "array":
            self.value_size = 0
            for item in self.value:
                self.value_size += item.update_size()
            return self.value_size + self.size
        if self.type == "fdict":
            self.value_size = 0
            for item in self.value:
                self.value_size += self.value[item].update_size()
            return self.value_size
        if self.type == "dict":
            self.value_size = 0
            for item in self.value:
                self.value_size += self.value[item].update_size()
            return self.value_size + self.size
        if self.type == "variant":
            self.value_size = self.value.update_size()
            return self.value_size + self.size
        error_unknown_type()

    def write(self, writer):
        self.update_size()
        self.write_(writer)

    def get_full_size(self):
        if self.type == "fbytes" or self.variant_type == "fdict":
            return self.value_size
        return self.value_size + self.size

    def write_(self, writer):
        if self.type == "fbytes":
            writer.write(self.value)
        if self.type == "bytes":
            writer.write(get_bytes_from_int(self.value_size, self.size))
            writer.write(self.value)
        if self.type == "fdict":
            for entry in self.value:
                self.value[entry].write_(writer)
        if self.type == "dict":
            writer.write(get_bytes_from_int(self.value_size, self.size))
            for entry in self.value:
                self.value[entry].write_(writer)
        if self.type == "array":
            writer.write(get_bytes_from_int(self.value_size, self.size))
            for entry in self.value:
                entry.write_(writer)
        if self.type == "variant":
            writer.write(get_bytes_from_int(self.variant_type, self.size))
            self.value.write_(writer)

    def to_bytes(self):
        buf = io.BytesIO()
        self.write(buf)
        buf.seek(0)
        return buf.read(self.get_full_size())

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





if __name__ == "__main__":
    test_array_of_bytes()
    test_array_of_fbytes()
    test_bytes()
    test_fbytes()
    test_dict()
    test_allias()
    test_variant()
    
