import io
from error import *


def skip_spaces(patternstream: io.StringIO):

    while True:
        res = patternstream.read(1)
        if len(res) == 0:
            return
        if res != ' ' and res != '\t' and res != '\n':
            patternstream.seek(patternstream.tell()-1)
            return


def peek(patternstream: io.StringIO):
    res = patternstream.read(1)
    if len(res) != 0:
        patternstream.seek(patternstream.tell()-1)
    return res


def get_bytes(input: io.BytesIO, size):
    result = bytearray()
    current = 0
    while size != 0:
        result.extend(input.read(size))
        if current == len(result):
            error_buffer_empty()
        size -= len(result) - current
        current = len(result)
    return result


def get_int(input: io.BytesIO, size):
    return int.from_bytes(get_bytes(input, size), 'big')

def get_bytes_from_int(value: int, size):
    return value.to_bytes(size, 'big')

