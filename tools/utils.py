import io
from tools.error import *
from collections import namedtuple


def reverse(m):
    for i in range(len(m)//2):
        tmp = m[i]
        m[i] = m[len(m)-1 - i]
        m[len(m)-1 - i] = tmp

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


def decode_OID(buffer: bytearray):
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

def encode_OID_singlet(value):
    first = True
    if value == 0:
        return bytearray(1)
    res = bytearray()
    while value > 0:
        
        res.append( value % 128 )
        if first:
            first = False
        else:
            res[-1] += 128    
        value //= 128

    reverse(res)
    return res

    
def encode_OID(buffer):
    res = bytearray()
    if len(buffer) == 0:
        error_buffer_empty()
    res.append( buffer[0]*40 +  buffer[1] % 40)

    index = 2
    
    while index != len(buffer):
        res.extend(encode_OID_singlet(buffer[index]))
        index += 1
    return res

    
def encode_OID_from_str(buffer:str):
    buffer = buffer[1:-1]
    values = [ int(v) for v in  buffer.split('.')]
    
    return encode_OID(values)




def get_int_size(value: int):
    cnt = 1
    while value >= 256:
        cnt += 1
        value //= 256
    return cnt


def get_length_size(length: int):
    if length < 128:
        return 1
    cnt = 1
    while length >= 256:
        cnt += 1
        length /= 256
    return cnt + 1


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


Variant = namedtuple("Variant", ["variant_type", "data"])

ASN = namedtuple("ASN", ["type", "data"])


def ASN_INT(value):
    return ASN("ASN_INT", value)

def ASN_BOOL(value):


    return ASN("ASN_BOOL", value)


def ASN_BIT(value):
    return ASN("ASN_BIT_STRING", bytearray.fromhex(value))


def ASN_OCT(value):
    return ASN("ASN_OCTET_STRING", bytearray.fromhex(value))

def ASN_OID(value):
    return ASN("ASN_OBJECT_IDENTIFIER", encode_OID_from_str(value))

def ASN_PRI(value):
    buffer = bytearray()
    buffer.extend(map(ord, value))
    return ASN("ASN_PRINTABLE_STRING", buffer)

def ASN_UTC(value):
    buffer = bytearray()
    buffer.extend(map(ord, value))
    return ASN("ASN_UTCTIME", buffer)

def ASN_GT(value):
    buffer = bytearray()
    buffer.extend(map(ord, value))
    return ASN("ASN_GeneralizedTime", buffer)




ASNSEQ = namedtuple("ASNSeq",  ["data"])
ASN_CST = namedtuple("ASNSeq",  ["tag", "data"])


def compare_result(result, expected):
    if isinstance(expected, Variant):
        assert result.variant_type == expected.variant_type
        compare_result(result.value, expected.data)
    elif isinstance(expected, ASN):
        assert result.type == expected.type
        compare_result(result, expected.data)
    elif isinstance(expected, ASNSEQ):
        assert result.type == "ASN_Sequence" or result.type == "ASN_Set"
        compare_result(result, expected.data)
    elif isinstance(expected, ASN_CST):
        assert result.type == "ASN_Context_Specific"
        assert result.variant_type == expected.tag
        compare_result(result.value, expected.data)
    elif isinstance(expected, dict):
        for k, v in expected.items():
            compare_result(result[k], v)
    elif isinstance(expected, list):
        for i, v in enumerate(expected):
            compare_result(result[i], v)
    else:
        if hasattr(result, 'value'):
            assert result.value == expected
        else:
            assert result == expected


