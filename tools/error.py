def error_buffer_empty():
    raise Exception("Buffer out of data!")


def error_unexpected_token():
    raise Exception("unexpected token!")


def error_incorrect_length_array():
    raise Exception("array has incorect length!")


def error_unknown_type():
    raise Exception("unknown type!")


def error_unknown_variant_type():
    raise Exception("unknown variant type!")


def error_incorrect_length_ASN_content_specific():
    raise Exception("ASN content specific has incorect length!")

def error_incorrect_length_ASN_sequence():
    raise Exception("ASN secuence has incorect length!")
