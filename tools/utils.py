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


def new_io_bytes_from_string(string: str):
    return io.BytesIO(bytearray.fromhex(string))


def parse_object_identifier(buffer: bytearray):
    if len(buffer) == 0:
        error_buffer_empty()
    res = [buffer[0]//40, buffer[0] % 40]

    index = 1
    flag = True
    while index != len(buffer):
        if flag:
            res.append(0)
            flag = False
        res[-1] *= 128
        res[-1] += buffer[index]
        if buffer[index] >= 128:
            res[-1] -= 128
        else:
            flag = True
        index += 1
    return res

def get_int_size(value:int):
    cnt = 1
    while value >= 256:
        cnt += 1
        value //= 256
    return cnt

def get_length_size(length:int):
    if length < 128:
        return 1
    cnt = 1
    while length >= 256:
        cnt += 1
        length /= 256
    return cnt  + 1

def encode_length(length, length_size):
    res = bytearray(length_size)
    if length_size == 1:
        res[0] = length
        return res
    res[0] = length_size + 127
    for i in range(length_size-1):
        res[-(i+1)] = length % 256
        length //= 256
    return res
    
    