

def XOR_8(lhs: bytearray, rhs: bytearray):
    if (len(lhs) != len(rhs)):
        raise Exception("XOR_8: byte arrays have different size")
    if (len(lhs) != 8):
        raise Exception(
            "XOR_8: byte arrays have length other than 64")
    result = lhs.copy()
    for i in range(8):
        result[i] ^= rhs[i]
    return result


def streebog_X_k_(k: bytearray, a: bytearray):
    if (len(a) != len(k)):
        raise Exception("X_k transformation: byte arrays have different size")
    if (len(a) != 64):
        raise Exception(
            "X_k transformation: byte arrays have length other than 64")
    result = a.copy()
    for i in range(64):
        result[i] ^= k[i]
    return result


streebog_pi_values_ = [252, 238, 221, 17, 207, 110, 49, 22, 251, 196, 250, 218, 35, 197, 4, 77, 233, 119, 240,
                       219, 147, 46, 153, 186, 23, 54, 241, 187, 20, 205, 95, 193, 249, 24, 101, 90, 226, 92, 239,
                       33, 129, 28, 60, 66, 139, 1, 142, 79, 5, 132, 2, 174, 227, 106, 143, 160, 6, 11, 237, 152, 127,
                       212, 211, 31, 235, 52, 44, 81, 234, 200, 72, 171, 242, 42, 104, 162, 253, 58, 206, 204, 181,
                       112, 14, 86, 8, 12, 118, 18, 191, 114, 19, 71, 156, 183, 93, 135, 21, 161, 150, 41, 16, 123,
                       154, 199, 243, 145, 120, 111, 157, 158, 178, 177, 50, 117, 25, 61, 255, 53, 138, 126, 109,
                       84, 198, 128, 195, 189, 13, 87, 223, 245, 36, 169, 62, 168, 67, 201, 215, 121, 214, 246, 124,
                       34, 185, 3, 224, 15, 236, 222, 122, 148, 176, 188, 220, 232, 40, 80, 78, 51, 10, 74, 167, 151,
                       96, 115, 30, 0, 98, 68, 26, 184, 56, 130, 100, 159, 38, 65, 173, 69, 70, 146, 39, 94, 85, 47,
                       140, 163, 165, 125, 105, 213, 149, 59, 7, 88, 179, 64, 134, 172, 29, 247, 48, 55, 107, 228,
                       136, 217, 231, 137, 225, 27, 131, 73, 76, 63, 248, 254, 141, 83, 170, 144, 202, 216, 133, 97,
                       32, 113, 103, 164, 45, 43, 9, 91, 203, 155, 37, 208, 190, 229, 108, 82, 89, 166, 116, 210,
                       230, 244, 180, 192, 209, 102, 175, 194, 57, 75, 99, 182]


def streebog_pi_(a):
    return streebog_pi_values_[a]


def streebog_S_(a: bytearray):
    if (len(a) != 64):
        raise Exception(
            "S transformation: byte arrays have length other than 64")
    result = a.copy()
    for i in range(64):
        result[i] = streebog_pi_(a[i])
    return result


streebog_tau_values_ = [0, 8, 16, 24, 32, 40, 48, 56, 1, 9, 17, 25, 33, 41, 49, 57, 2, 10, 18, 26, 34, 42, 50, 58,
                        3, 11, 19, 27, 35, 43, 51, 59, 4, 12, 20, 28, 36, 44, 52, 60, 5, 13, 21, 29, 37, 45, 53, 61, 6, 14,
                        22, 30, 38, 46, 54, 62, 7, 15, 23, 31, 39, 47, 55, 63]


def streebog_P_(a: bytearray):
    if (len(a) != 64):
        raise Exception(
            "P transformation: byte arrays have length other than 64")
    result = a.copy()
    for i in range(64):
        result[i] = a[streebog_tau_values_[i]]
    return result


streebog_a_values_ = [bytearray(b'\x8e \xfa\xa7+\xa0\xb4p'), bytearray(b'G\x10}\xdd\x9bPZ8'), bytearray(b'\xad\x08\xb0\xe0\xc3(-\x1c'), bytearray(b'\xd8\x04Xp\xef\x14\x98\x0e'), bytearray(b'l\x02,8\xf9\nL\x07'), bytearray(b'6\x01\x16\x1c\xf2\x05&\x8d'), bytearray(b'\x1b\x8e\x0b\x0ey\x8c\x13\xc8'), bytearray(b'\x83G\x8b\x07\xb2F\x87d'), bytearray(b'\xa0\x11\xd3\x80\x81\x8e\x8f@'), bytearray(b'P\x86\xe7@\xceG\xc9 '), bytearray(b'(C\xfd g\xad\xea\x10'), bytearray(b'\x14\xaf\xf0\x10\xbd\xd8u\x08'), bytearray(b'\n\xd9x\x08\xd0l\xb4\x04'), bytearray(b'\x05\xe2<\x04h6Z\x02'), bytearray(b'\x8cq\x1e\x024\x1b-\x01'), bytearray(b'F\xb6\x0f\x01\x1a\x83\x98\x8e'), bytearray(b'\x90\xda\xb5*8z\xe7o'), bytearray(b'Hm\xd4\x15\x1c=\xfd\xb9'), bytearray(b'$\xb8j\x84\x0e\x90\xf0\xd2'), bytearray(b'\x12\\5B\x07Hxi'), bytearray(b'\t.\x94!\x8d$<\xba'), bytearray(b'\x8a\x17J\x9e\xc8\x12\x1e]'), bytearray(b'E\x85%Od\t\x0f\xa0'), bytearray(b'\xac\xcc\x9c\xa92\x8a\x89P'), bytearray(b'\x9dM\xf0]_f\x14Q'), bytearray(b'\xc0\xa8x\xa0\xa13\n\xa6'), bytearray(b'`T<P\xde\x97\x05S'), bytearray(b'0*\x1e(o\xc5\x8c\xa7'), bytearray(b'\x18\x15\x0f\x14\xb9\xecF\xdd'), bytearray(b'\x0c\x84\x89\n\xd2v#\xe0'), bytearray(b'\x06B\xca\x05i;\x9fp'), bytearray(
    b'\x03!e\x8c\xba\x93\xc18'), bytearray(b"\x86\']\xf0\x9c\xe8\xaa\xa8"), bytearray(b'C\x9d\xa0xNtUT'), bytearray(b"\xaf\xc0P<\':\xa4*"), bytearray(b'\xd9`(\x1e\x9d\x1dR\x15'), bytearray(b'\xe20\x14\x0f\xc0\x80)\x84'), bytearray(b'q\x18\n\x89`@\x9aB'), bytearray(b'\xb6\x0c\x05\xca0 M!'), bytearray(b'[\x06\x8ce\x18\x10\xa8\x9e'), bytearray(b'El4\x88z8\x05\xb9'), bytearray(b'\xac6\x1aD=\x1c\x8c\xd2'), bytearray(b'V\x1b\r"\x90\x0eFi'), bytearray(b'+\x83\x88\x11H\x07#\xba'), bytearray(b'\x9b\xcfD\x86$\x8d\x9f]'), bytearray(b'\xc3\xe9"C\x12\xc8\xc1\xa0'), bytearray(b'\xef\xfa\x11\xaf\td\xeeP'), bytearray(b'\xf9}\x86\xd9\x8a2w('), bytearray(b'\xe4\xfa T\xa8\x0b2\x9c'), bytearray(b'r}\x10*T\x8b\x19N'), bytearray(b"9\xb0\x08\x15*\xcb\x82\'"), bytearray(b'\x92X\x04\x84\x15\xebA\x9d'), bytearray(b'I,\x02B\x84\xfb\xae\xc0'), bytearray(b'\xaa\x16\x01!B\xf3W`'), bytearray(b'U\x0b\x8e\x9e!\xf7\xa50'), bytearray(b'\xa4\x8bGO\x9e\xf5\xdc\x18'), bytearray(b'p\xa6\xa5n$@Y\x8e'), bytearray(b'8S\xdc7\x12 \xa2G'), bytearray(b'\x1c\xa7n\x95\t\x10Q\xad'), bytearray(b'\x0e\xdd7\xc4\x8a\x08\xa6\xd8'), bytearray(b'\x07\xe0\x95bE\x04Sl'), bytearray(b'\x8dp\xc41\xac\x02\xa76'), bytearray(b'\xc88b\x96V\x01\xdd\x1b'), bytearray(b'd\x1c1K+\x8e\xe0\x83')]


def streebog_l_(a: bytearray):
    if len(a) != 8:
        raise Exception(
            "l transformation: byte array has length other than 8")
    result = bytearray(8)
    a = int.from_bytes(a, byteorder='big', signed=False)
    cnt = 63
    while a:
        if (a % 2):
            result = XOR_8(result, streebog_a_values_[cnt])
        cnt -= 1
        a = a // 2
    return result


def streebog_L_(a: bytearray):
    result = bytearray(0)
    for i in range(8):
        result += streebog_l_(a[i*8:i*8+8])
    return result


def streebog_LPS_(a: bytearray):
    result = a.copy()
    result = streebog_S_(result)
    result = streebog_P_(result)
    result = streebog_L_(result)
    return result


streebog_C_values = [bytearray(b'\xb1\x08[\xda\x1e\xca\xda\xe9\xeb\xcb/\x81\xc0e|\x1f/jvC.E\xd0\x16qN\xb8\x8du\x85\xc4\xfcK|\xe0\x91\x92gi\x01\xa2B*\x08\xa4`\xd3\x15\x05vt6\xcctM#\xdd\x80eY\xf2\xa6E\x07'), bytearray(b'o\xa3\xb5\x8a\xa9\x9d/\x1aO\xe3\x9dF\x0fp\xb5\xd7\xf3\xfe\xear\n#+\x98a\xd5^\x0f\x16\xb5\x011\x9a\xb5\x17k\x12\xd6\x99X\\\xb5a\xc2\xdb\n\xa7\xcaU\xdd\xa2\x1b\xd7\xcb\xcdV\xe6y\x04p!\xb1\x9b\xb7'), bytearray(b'\xf5t\xdc\xac+\xce/\xc7\n9\xfc(j=\x845\x06\xf1^_R\x9c\x1f\x8b\xf2\xeau\x14\xb1){{\xd3\xe2\x0f\xe4\x905\x9e\xb1\xc1\xc9:7`b\xdb\t\xc2\xb6\xf4C\x86z\xdb1\x99\x1e\x96\xf5\n\xba\n\xb2'), bytearray(b'\xef\x1f\xdf\xb3\xe8\x15f\xd2\xf9H\xe1\xa0]q\xe4\xddH\x8e\x85~3\\<}\x9dr\x1c\xadh^5?\xa9\xd7,\x82\xed\x03\xd6u\xd8\xb7\x133\x93R\x03\xbe4S\xea\xa1\x93\xe87\xf1"\x0c\xbe\xbc\x84\xe3\xd1.'), bytearray(b"K\xeak\xac\xadGG\x99\x9a?A\x0cl\xa9#c\x7f\x15\x1c\x1f\x16\x86\x10J5\x9e5\xd7\x80\x0f\xff\xbd\xbf\xcd\x17G%:\xf5\xa3\xdf\xff\x00\xb7#\'\x1a\x16zV\xa2~\xa9\xeac\xf5`\x17X\xfd|l\xfeW"), bytearray(b'\xaeO\xae\xae\x1d:\xd3\xd9o\xa4\xc3;z09\xc0-f\xc4\xf9QB\xa4l\x18\x7f\x9a\xb4\x9a\xf0\x8e\xc6\xcf\xfa\xa6\xb7\x1c\x9a\xb7\xb4\n\xf2\x1ff\xc2\xbe\xc6\xb6\xbfq\xc5r6\x90O5\xfah@zFd}n'), bytearray(
    b'\xf4\xc7\x0e\x16\xee\xaa\xc5\xecQ\xac\x86\xfe\xbf$\tT9\x9e\xc6\xc7\xe6\xbf\x87\xc9\xd3G>3\x19z\x93\xc9\t\x92\xab\xc5-\x82,7\x06Gi\x83(J\x05\x045\x17EL\xa2<J\xf3\x88\x86VM:\x14\xd4\x93'), bytearray(b'\x9b\x1f[BM\x93\xc9\xa7\x03\xe7\xaa\x02\x0cnAAN\xb7\xf8q\x9c6\xde\x1e\x89\xb4D;M\xdb\xc4\x9a\xf4\x89+\xcb\x92\x9b\x06\x90i\xd1\x8d+\xd1\xa5\xc4/6\xac\xc25YQ\xa8\xd9\xa4\x7f\r\xd4\xbf\x02\xe7\x1e'), bytearray(b'7\x8fZT\x161"\x9b\x94L\x9a\xd8\xec\x16_\xde:}:\x1b%\x89B$<\xd9U\xb7\xe0\r\t\x84\x80\nD\x0b\xdb\xb2\xce\xb1{+\x8a\x9a\xa6\x07\x9cT\x0e8\xdc\x92\xcb\x1f*`raDQ\x83#Z\xdb'), bytearray(b'\xab\xbe\xde\xa6\x80\x05oR8*\xe5H\xb2\xe4\xf3\xf3\x89A\xe7\x1c\xff\x8ax\xdb\x1f\xff\xe1\x8a\x1b3a\x03\x9f\xe7g\x02\xafi3Kz\x1el0;vR\xf46\x98\xfa\xd1\x15;\xb6\xc3t\xb4\xc7\xfb\x98E\x9c\xed'), bytearray(b'{\xcd\x9e\xd0\xef\xc8\x89\xfb0\x02\xc6\xcdcZ\xfe\x94\xd8\xfak\xbb\xeb\xab\x07a \x01\x80!\x14\x84fy\x8a\x1dq\xef\xeaH\xb9\xca\xef\xba\xcd\x1d}Gn\x98\xde\xa2YJ\xc0o\xd8]k\xca\xa4\xcd\x81\xf3-\x1b'), bytearray(b'7\x8e\xe7g\xf1\x161\xba\xd2\x13\x80\xb0\x04I\xb1z\xcd\xa4<2\xbc\xdf\x1dw\xf8 \x12\xd40!\x9f\x9b]\x80\xef\x9d\x18\x91\xcc\x86\xe7\x1d\xa4\xaa\x88\xe1(R\xfa\xf4\x17\xd5\xd9\xb2\x1b\x99H\xbc\x92J\xf1\x1b\xd7 ')]


def streebog_E_(K: bytearray, m: bytearray):
    result = m.copy()
    K = K.copy()
    result = streebog_X_k_(K, result)
    for i in range(12):
        result = streebog_LPS_(result)
        K = streebog_X_k_(streebog_C_values[i], K)
        K = streebog_LPS_(K)
        result = streebog_X_k_(K, result)
    return result


def streebog_G_(N: bytearray, h: bytearray, m: bytearray):
    return streebog_X_k_(streebog_X_k_(streebog_E_(streebog_LPS_(streebog_X_k_(h, N)), m), h), m)


def startwith_1_hex_(m: bytearray):
    result = bytearray(64)

    first = True
    for i in range(len(m)):
        if first:
            if m[i] != 0:
                if m[i] >= 16:
                    result[64-len(m) + i - 1] = 1
                    result[64-len(m) + i] = m[i]
                else:
                    result[64-len(m) + i] = m[i] + 16
                first = False
        else:
            result[64-len(m) + i] = m[i]
    return result


def add_int_(lhs: bytearray, rhs: int):
    result = lhs.copy()
    result = bytearray(int(int.from_bytes(result, "big") +
                           rhs).to_bytes(64, "big"))
    return result


def add_as_ints(lhs: bytearray, rhs: bytearray):
    return add_int_(lhs, int.from_bytes(rhs, "big"))


def len_of_bytearray_hex(a: bytearray):
    for i in range(len(a)):
        if a[i] != 0:
            if a[i] >= 16:
                return (len(a) - i) * 8
            else:
                return (len(a) - i) * 8 - 4
    return 0


def streebog_hex(Message: bytearray, mode=512):
    if mode == 512:
        IV = bytearray(64)
    else:
        IV = bytearray(b'\x01'*64)
    h = IV.copy()
    N = bytearray(64)
    Sigma = bytearray(64)
    M = Message.copy()
    while (len(M) > 64 or (len(M) == 64 and M[0] > 128)):
        m = M[-64:]
        h = streebog_G_(N, h, m)
        N = add_int_(N, 512)
        Sigma = add_as_ints(Sigma, m)
        M = M[:-64]
    m = startwith_1_hex_(M)
    h = streebog_G_(N, h, m)
    N = add_int_(N, len_of_bytearray_hex(M))
    Sigma = add_as_ints(Sigma, m)
    tmp = bytearray(64)
    h = streebog_G_(tmp, h, N)
    h = streebog_G_(tmp, h, Sigma)
    if mode == 512:
        return h
    else:
        return h[:32]
