
from enum import Enum
import io

from error import *
from utils import *


class TokenType(Enum):
    const = 0
    name = 1
    left_bracket = 2
    right_bracket = 3
    comma = 4
    error = 10


class Token:
    def __init__(self, patternstream: io.StringIO):
        self.size = 0
        self.value = None
        skip_spaces(patternstream)
        res = patternstream.read(1)
        if len(res) == 0:
            error_buffer_empty()
        elif res[0] == '(':
            self.size = 1
            self.type = TokenType.left_bracket
        elif res[0] == ')':
            self.size = 1
            self.type = TokenType.right_bracket
        elif res[0] == ',':
            self.size = 1
            self.type = TokenType.comma
        elif res[0].isdigit():
            self.type = TokenType.const
            patternstream.seek(patternstream.tell()-1)
            self.value = get_const_token(patternstream)
        elif res[0].isalpha:
            self.type = TokenType.name
            self.value = res + get_name_token(patternstream)
        else:
            self.type = TokenType.error


def get_const_token(patternstream: io.StringIO):
    value = 0
    while True:
        res = patternstream.read(1)
        if len(res) == 0:
            return value
        if not res[0].isdigit():
            patternstream.seek(patternstream.tell()-1)
            return value

        value *= 10
        value += ord(res[0]) - ord('0')


def get_name_token(patternstream: io.StringIO):
    res = ''
    while True:
        res += patternstream.read(1)
        if len(res) == 0:
            return res
        if not res[-1].isalnum():
            patternstream.seek(patternstream.tell()-1)
            return res[:-1]


def get_token_with_type(patternstream: io.StringIO, type: TokenType):
    token = Token(patternstream)
    if token.type != type:
        error_unexpected_token()
    return token
