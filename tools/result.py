from error import *
from utils import *
from binascii import hexlify


class Result:
    def __init__(self, type, value, size, value_size=0, variant_type=0):
        self.type = type
        self.value = value
        self.size = size
        self.value_size = value_size
        self.variant_type = variant_type

    def to_printable_string(self, offset=""):
        if self.type == "ASN_BOOL":
            return offset + "ASN Bool size " + str(self.size) + " value size " + str(
                self.value_size) + " with value : " + str(self.value)
        if self.type == "ASN_INT":
            return offset + "ASN integer size " + str(self.size) + " value size " + str(
                self.value_size) + " with value : " + str(self.value)
        if self.type == "ASN_BIT_STRING":
            return offset + "ASN_BIT_STRING size " + str(self.size) + " value size " + str(
                self.value_size) + " that skips " + str(self.value[0]) + " bits with value " + str(
                hexlify(self.value[1:]))
        if self.type == "ASN_OCTET_STRING":
            return offset + "ASN_OCTET_STRING size " + str(self.size) + " value size " + str(
                self.value_size) + " with value : " + str(hexlify(self.value))
        if self.type == "ASN_OBJECT_IDENTIFIER":
            return offset + "ASN_OBJECT_IDENTIFIER size " + str(self.size) + " value size " + str(
                self.value_size) + " with value : " + str(decode_OID(self.value))
        if self.type == "ASN_PRINTABLE_STRING":
            return offset + "ASN_PRINTABLE_STRING size " + str(self.size) + " value size " + str(
                self.value_size) + " with value : \"" + str(self.value.decode()) + "\""
        if self.type == "ASN_IA5String":
            return offset + "ASN_IA5String size " + str(self.size) + " value size " + str(
                self.value_size) + " with value : \"" + str(self.value.decode()) + "\""
        if self.type == "ASN_UTCTIME":
            return offset + "ASN_UTCTIME size " + str(self.size) + " value size " + str(
                self.value_size) + " with value : \"" + str(self.value.decode()) + "\""
        if self.type == "ASN_GeneralizedTime":
            return offset + "ASN_GeneralizedTime size " + str(self.size) + " value size " + str(
                self.value_size) + " with value : \"" + str(self.value.decode()) + "\""
        if self.type == "ASN_Context_Specific":
            return offset + "ASN_Context_Specific size " + str(self.size) + " value size " + str(
                self.value_size) + " with id : " + str(
                self.variant_type) + " with value:\n" + self.value.to_printable_string(offset + "  ")
        if self.type == "ASN_Sequence":
            string = offset + "ASN_Sequence size " + \
                     str(self.size) + " value size " + \
                     str(self.value_size) + "  with values:"
            for item in self.value:
                string += "\n"
                string += item.to_printable_string(offset + "  ")
            return string
        if self.type == "ASN_Set":
            string = offset + "ASN_Set  size " + \
                     str(self.size) + " value size " + \
                     str(self.value_size) + "  with values:"
            for item in self.value:
                string += "\n"
                string += item.to_printable_string(offset + "  ")
            return string
        if self.type == "ASN_Unknown":
            return offset + "ASN_IA5String size " + str(self.size) + " with type " + str(
                self.type) + " value size " + str(self.value_size) + " with value : \"" + str(
                self.value.decode()) + "\""
        if self.type == "fbytes":
            return offset + "fbytes with value :" + str(hexlify(self.value))
        if self.type == "bytes":
            return offset + "bytes of length size : " + str(self.size) + " with value :" + str(hexlify(self.value))
        if self.type == "array":
            string = offset + "array of length size : " + \
                     str(self.size) + " with values:"
            for item in self.value:
                string += "\n"
                string += item.to_printable_string(offset + "  ")
            return string
        if self.type == "fdict":
            string = offset + "fdict with values:"
            for item in self.value:
                string += " \n" + offset + "  key : " + item
                string += "  value:\n"
                string += self.value[item].to_printable_string(offset + "  ")
            return string
        if self.type == "dict":
            string = offset + "dict of length size : " + \
                     str(self.size) + " with values:"
            for item in self.value:
                string += " \n" + offset + "  key : " + item
                string += "  value:\n"
                string += self.value[item].to_printable_string(offset + "  ")
            return string
        if self.type == "variant":
            return offset + "variant with id : " + str(
                self.variant_type) + " with value:\n" + self.value.to_printable_string(offset + "  ")

        return "Result type: " + self.type + " value: " + str(self.value)

    def __str__(self) -> str:
        return self.to_printable_string()

    def __repr__(self):
        return self.to_printable_string()

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
        if self.type == "ASN_BOOL":
            self.size = 1
            self.value_size = 1
            return 3
        if self.type == "ASN_INT":
            self.value_size = get_int_size(self.value)
            self.size = get_length_size(self.value_size)
            return 1 + self.value_size + self.size
        if self.type == "ASN_BIT_STRING" or self.type == "ASN_OCTET_STRING" or self.type == "ASN_OCTET_STRING" or self.type == "ASN_OBJECT_IDENTIFIER" or self.type == "ASN_PRINTABLE_STRING" or self.type == "ASN_UTCTIME" or self.type == "ASN_GeneralizedTime" or self.type == "ASN_IA5String" or self.type == "ASN_Unknown":
            self.value_size = len(self.value)
            self.size = get_length_size(self.value_size)
            return 1 + self.value_size + self.size
        if self.type == "ASN_Context_Specific":
            self.value_size = self.value.update_size()
            self.size = get_length_size(self.value_size)
            return 1 + self.value_size + self.size
        if self.type == "ASN_Sequence" or self.type == "ASN_Set":
            self.value_size = 0
            for item in self.value:
                self.value_size += item.update_size()
            self.size = get_length_size(self.value_size)
            return 1 + self.value_size + self.size

        error_unknown_type()

    def write(self, writer):
        self.update_size()
        self.write_(writer)

    def get_full_size(self):
        if self.type == "fbytes" or self.variant_type == "fdict":
            return self.value_size
        if self.type.startswith("ASN"):
            return self.value_size + self.size + 1
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
        if self.type == "ASN_BOOL":
            writer.write(get_bytes_from_int(1, 1))
            writer.write(get_bytes_from_int(1, 1))
            if self.value:
                writer.write(get_bytes_from_int(255, 1))
            else:
                writer.write(get_bytes_from_int(0, 1))
        if self.type == "ASN_INT":
            writer.write(get_bytes_from_int(2, 1))
            writer.write(encode_length(self.value_size, self.size))
            writer.write(
                bytearray(self.value.to_bytes(self.value_size, 'big')))

        if self.type == "ASN_BIT_STRING":
            writer.write(get_bytes_from_int(3, 1))
            writer.write(encode_length(self.value_size, self.size))
            writer.write(self.value)
        if self.type == "ASN_OCTET_STRING":
            writer.write(get_bytes_from_int(4, 1))
            writer.write(encode_length(self.value_size, self.size))
            writer.write(self.value)
        if self.type == "ASN_OBJECT_IDENTIFIER":
            writer.write(get_bytes_from_int(6, 1))
            writer.write(encode_length(self.value_size, self.size))
            writer.write(self.value)
        if self.type == "ASN_PRINTABLE_STRING":
            writer.write(get_bytes_from_int(19, 1))
            writer.write(encode_length(self.value_size, self.size))
            writer.write(self.value)
        if self.type == "ASN_IA5String":
            writer.write(get_bytes_from_int(22, 1))
            writer.write(encode_length(self.value_size, self.size))
            writer.write(self.value)
        if self.type == "ASN_UTCTIME":
            writer.write(get_bytes_from_int(23, 1))
            writer.write(encode_length(self.value_size, self.size))
            writer.write(self.value)
        if self.type == "ASN_GeneralizedTime":
            writer.write(get_bytes_from_int(24, 1))
            writer.write(encode_length(self.value_size, self.size))
            writer.write(self.value)
        if self.type == "ASN_Context_Specific":
            writer.write(get_bytes_from_int(160 + self.variant_type, 1))
            writer.write(encode_length(self.value_size, self.size))
            self.value.write_(writer)
        if self.type == "ASN_Sequence":
            writer.write(get_bytes_from_int(48, 1))
            writer.write(encode_length(self.value_size, self.size))
            for item in self.value:
                item.write_(writer)
        if self.type == "ASN_Set":
            writer.write(get_bytes_from_int(49, 1))
            writer.write(encode_length(self.value_size, self.size))
            for item in self.value:
                item.write_(writer)

    def to_bytes(self):
        buf = io.BytesIO()
        self.write(buf)
        buf.seek(0)
        return buf.read(self.get_full_size())


def fbyteresult(string: str):
    value = bytearray.fromhex(string)
    return Result("fbytes", value, len(value), len(value))


def variant(v_type, size, value):
    return Result("variant", value, size, 0, variant_type=v_type)
