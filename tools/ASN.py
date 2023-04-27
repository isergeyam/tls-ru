import io
from utils import *

from result import Result
import binascii


def read_length(buffer):
    first = get_bytes(buffer, 1)[0]
    if first < 128:
        return first
    else:
        return get_int(buffer, first - 128)


def read_type(buffer):
    first = get_bytes(buffer, 1)[0]
    return first


def parse_ASN(buffer: io.BytesIO):
    type = read_type(buffer)
    length = read_length(buffer)
    if type == 1:
        value = get_int(buffer, length)
        return Result("ASN_BOOL", value != 0, 0, 0)
    if type == 2:
        return Result("ASN_INT", get_int(buffer, length), 0, 0)
    if type == 3:
        return Result("ASN_BIT_STRING", get_bytes(buffer, length), 0, 0)
    if type == 4:
        return Result("ASN_OCTET_STRING", get_bytes(buffer, length), 0, 0)
    if type == 6:
        return Result("ASN_OBJECT_IDENTIFIER", get_bytes(buffer, length), 0, 0)
    if type == 19:
        return Result("ASN_PRINTABLE_STRING", get_bytes(buffer, length), 0, 0)
    if type == 22:
        return Result("ASN_IA5String", get_bytes(buffer, length), 0, 0)
    if type == 23:
        return Result("ASN_UTCTIME", get_bytes(buffer, length), 0, 0)
    if type == 24:
        return Result("ASN_GeneralizedTime", get_bytes(buffer, length), 0, 0)
    if type == 48 or type == 49:
        values = []
        start = buffer.tell()
        while start + length > buffer.tell():
            values.append(parse_ASN(buffer))
        if start + length != buffer.tell():
            error_incorrect_length_ASN_sequence()
        if type == 48:
            return Result("ASN_Sequence", values, 0, 0)
        else:
            return Result("ASN_Set", values, 0, 0)

    if type >= 160:
        start = buffer.tell()
        value = parse_ASN(buffer)
        if start + length != buffer.tell():
            error_incorrect_length_ASN_content_specific()
        return Result("ASN_Context_Specific", value, 0, 0, variant_type=type - 160)


def test_INT():
    mybufferstream = new_io_bytes_from_string("02 01 02")

    print(parse_ASN(mybufferstream))


def test_BITE():
    mybufferstream = new_io_bytes_from_string("""03 43 00 04 40
                    0bd86fe5d8db89668f789b4e1dba8585
                    c5508b45ec5b59d8906ddb70e2492b7f
                    da77ff871a10fbdf2766d293c5d164af
                    bb3c7b973a41c885d11d70d689b4f126""")

    print(parse_ASN(mybufferstream))


def test_OCTET():
    mybufferstream = new_io_bytes_from_string("""04 40
                    0bd86fe5d8db89668f789b4e1dba8585
                    c5508b45ec5b59d8906ddb70e2492b7f
                    da77ff871a10fbdf2766d293c5d164af
                    bb3c7b973a41c885d11d70d689b4f126""")

    print(parse_ASN(mybufferstream))


def test_OBJ_ID():

    mybufferstream = new_io_bytes_from_string(
        """06 08 2a 85 03 07 01 01 03 02""")

    print(parse_ASN(mybufferstream))


def test_Printable():

    mybufferstream = new_io_bytes_from_string(
        """13 07 45 78 61 6d 70 6c 65""")

    print(parse_ASN(mybufferstream))


def test_TIME():
    mybufferstream = new_io_bytes_from_string(
        """17 0d 3031303130313030303030305a
            18 0f 32303530313233313030303030305a""")

    print(parse_ASN(mybufferstream))
    print(parse_ASN(mybufferstream))


def test_Seq():
    mybufferstream = new_io_bytes_from_string(
        """30 12 
            31 10
                30 0e
                    06 03 55 04 03
                    13 07 45 78 61 6d 70 6c 65
        """)

    print(parse_ASN(mybufferstream))


def test_SERT():
    mybuffer = bytearray.fromhex("""3082012d3081dba00302010202010a300a06082a8503070101030230123110300e060355040313074578616d706c653020170d3031303130313030303030305a180f32303530313233313030303030305a30123110300e060355040313074578616d706c653066301f06082a85030701010101301306072a85030202230006082a8503070101020203430004400bd86fe5d8db89668f789b4e1dba8585c5508b45ec5b59d8906ddb70e2492b7fda77ff871a10fbdf2766d293c5d164afbb3c7b973a41c885d11d70d689b4f126a3133011300f0603551d130101ff040530030101ff300a06082a850307010103020341004d53f012fe081776507d4d9bb81f00efdb4eefd4ab83bac4bacf735173cfa81c41aa28d2f1ab148280cd9ed56feda41974053554a42767b83ad043fd39dc0493""")
    mybufferstream = new_io_bytes_from_string(
        """3082012d3081dba00302010202010a300a06082a8503070101030230123110300e060355040313074578616d706c653020170d3031303130313030303030305a180f32303530313233313030303030305a30123110300e060355040313074578616d706c653066301f06082a85030701010101301306072a85030202230006082a8503070101020203430004400bd86fe5d8db89668f789b4e1dba8585c5508b45ec5b59d8906ddb70e2492b7fda77ff871a10fbdf2766d293c5d164afbb3c7b973a41c885d11d70d689b4f126a3133011300f0603551d130101ff040530030101ff300a06082a850307010103020341004d53f012fe081776507d4d9bb81f00efdb4eefd4ab83bac4bacf735173cfa81c41aa28d2f1ab148280cd9ed56feda41974053554a42767b83ad043fd39dc0493"""
    )
    print(len("3082012d3081dba00302010202010a300a06082a8503070101030230123110300e060355040313074578616d706c653020170d3031303130313030303030305a180f32303530313233313030303030305a30123110300e060355040313074578616d706c653066301f06082a85030701010101301306072a85030202230006082a8503070101020203430004400bd86fe5d8db89668f789b4e1dba8585c5508b45ec5b59d8906ddb70e2492b7fda77ff871a10fbdf2766d293c5d164afbb3c7b973a41c885d11d70d689b4f126a3133011300f0603551d130101ff040530030101ff300a06082a850307010103020341004d53f012fe081776507d4d9bb81f00efdb4eefd4ab83bac4bacf735173cfa81c41aa28d2f1ab148280cd9ed56feda41974053554a42767b83ad043fd39dc0493"))
    res = parse_ASN(mybufferstream)
    print(res.update_size())
    print(res)

    buf = io.BytesIO()

    print(res.write(buf))

    print()

    buf.seek(0)

    out = buf.read(res.get_full_size())
    print(binascii.hexlify(out))

    assert out == mybuffer


def test_rest():
    mybufferstream = new_io_bytes_from_string("82 01 2d")

    print(read_length(mybufferstream))

    mybufferstream = new_io_bytes_from_string("02 01 2d")

    print(read_length(mybufferstream))
    print(read_length(mybufferstream))
    print(read_length(mybufferstream))


if __name__ == "__main__":

    print(get_length_size(301))

    test_SERT()
