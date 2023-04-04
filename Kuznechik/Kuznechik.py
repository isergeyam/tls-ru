import binascii
import time

def reverse(m):
    for i in range(len(m)//2):
        tmp = m[i]
        m[i] = m[len(m)-1 - i]
        m[len(m)-1 - i] = tmp

def tobyte(a: int):
    return bytearray(a.to_bytes(64, 'big'))


def prin(a):
    print(binascii.hexlify(tobyte(a)))


operand = [148, 32, 133, 16, 194, 192, 251]

nonlinear = [252, 238, 221, 17, 207, 110, 49, 22, 251, 196, 250, 218, 35, 197, 4, 77, 233, 119, 240,
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

nonlinear_inv = [0 for i in range(256)]


def Prcompute_nonlinear_inverse():
    for i in range(256):
        nonlinear_inv[nonlinear[i]] = i
    


precomputed_LS = [[0 for i in range(256)] for j in range(16)]
precomputed_L_inv = [[0 for i in range(256)] for j in range(16)]

kkey = [0 for j in range(10)]


def GauloisMult(lhs, rhs):
    tmp_lhs = lhs
    tmp_rhs = rhs
    result = 0
    while (tmp_lhs != 0):
        if (tmp_lhs % 2 == 1):
            result ^= tmp_rhs
        tmp_rhs *= 2
        tmp_lhs //= 2
    q = 1 << 15
    mod = 451 * (1 << 7)
    while (q >= 256):
        if (result // q == 1):
            result ^= mod
        mod //= 2
        q //= 2
    return result % 256


def l_transformation(v):
    teration = 0
    tmp = v[0]
    tmp ^= GauloisMult(
        operand[0], v[teration + 1] ^ v[teration + 15])
    tmp ^= GauloisMult(
        operand[1], v[teration + 2] ^ v[teration + 14])
    tmp ^= GauloisMult(
        operand[2], v[teration + 3] ^ v[teration + 13])
    tmp ^= GauloisMult(
        operand[3], v[teration + 4] ^ v[teration + 12])
    tmp ^= GauloisMult(
        operand[4], v[teration + 5] ^ v[teration + 11])
    tmp ^= GauloisMult(
        operand[5], v[teration + 6] ^ v[teration + 10])
    tmp ^= v[teration + 7] ^ v[teration + 9]
    tmp ^= GauloisMult(operand[6], v[teration + 8])
    return tmp

def R_transformation( v):
    
    tmp = l_transformation(v)
    for i in range(15):
        v[i] = v[i + 1]

    v[15] = tmp

def R_transformation_inv( v):
    
    tmp = v[15]
    for i in range(14,-1, -1):
        v[i+1] = v[i]
    v[0] = tmp
    
    v[0] = l_transformation(v)
    



def Precompute_LS():
    v = [0 for i in range(32)]

    for i in range(16):
        v[i] = 0
        v[i + 16] = 0

    for pos in range(16):
        for x in range(256):
            for i in range(16):
                v[i] = 0
                v[i + 16] = 0
            v[pos] = nonlinear[x]
            precomputed_LS[pos][x] = Linear_array(v)
            



def Precompute_LS_inv():
    v = [0 for _ in range(16)]


    for pos in range(16):
        for x in range(256):
            for i in range(16):
                v[i] = 0
            v[pos] = x

            tmp = int.from_bytes(v, 'little')
            tmp = Linear_inverse(tmp)

            
            precomputed_L_inv[pos][x] = tmp

def Linear(tmp):
    vv = tmp.to_bytes(16, 'little')
    v = bytearray(32)
    for i in range(16):
        v[i] = 0
        v[i + 16] = 0
    for pos in range(16):
        v[pos] = vv[pos]
    for teration in range(16):
        tmp = v[teration]
        tmp ^= GauloisMult(
            operand[0], v[teration + 1] ^ v[teration + 15])
        tmp ^= GauloisMult(
            operand[1], v[teration + 2] ^ v[teration + 14])
        tmp ^= GauloisMult(
            operand[2], v[teration + 3] ^ v[teration + 13])
        tmp ^= GauloisMult(
            operand[3], v[teration + 4] ^ v[teration + 12])
        tmp ^= GauloisMult(
            operand[4], v[teration + 5] ^ v[teration + 11])
        tmp ^= GauloisMult(
            operand[5], v[teration + 6] ^ v[teration + 10])
        tmp ^= v[teration + 7] ^ v[teration + 9]
        tmp ^= GauloisMult(operand[6], v[teration + 8])
        v[16 + teration] = tmp
    res = 0
    q = 1
    for i in range(16):
        res += q * v[16 + i]
        q *= 256
    return res


def Linear_array(v):
    for teration in range(16):
        tmp = v[teration]
        tmp ^= GauloisMult(
            operand[0], v[teration + 1] ^ v[teration + 15])
        tmp ^= GauloisMult(
            operand[1], v[teration + 2] ^ v[teration + 14])
        tmp ^= GauloisMult(
            operand[2], v[teration + 3] ^ v[teration + 13])
        tmp ^= GauloisMult(
            operand[3], v[teration + 4] ^ v[teration + 12])
        tmp ^= GauloisMult(
            operand[4], v[teration + 5] ^ v[teration + 11])
        tmp ^= GauloisMult(
            operand[5], v[teration + 6] ^ v[teration + 10])
        tmp ^= v[teration + 7] ^ v[teration + 9]
        tmp ^= GauloisMult(operand[6], v[teration + 8])
        v[16 + teration] = tmp
    res = 0
    q = 1
    for i in range(16):
        res += q * v[16 + i]
        q *= 256
    return res
    

def Linear_inverse(tmp):
    vv = tmp.to_bytes(16, 'little')
    v = bytearray(32)
    for i in range(16):
        v[i] = 0
        v[i + 16] = 0
    for pos in range(16):
        v[pos] = vv[pos]
    for teration in range(16):
        R_transformation_inv(v)
    res = 0
    q = 1
    for i in range(16):
        res += q * v[i]
        q *= 256
    return res

def S_inverse(tmp):
    vv = tmp.to_bytes(16, 'little')
    v = bytearray(16)
    
    for pos in range(16):
        v[pos] = nonlinear_inv[ vv[pos]]
    res = 0
    q = 1
    for i in range(16):
        res += q * v[i]
        q *= 256
    return res

def LS_inverse(tmp):
    return S_inverse(Linear_inverse(tmp))


C = [Linear(i + 1) for i in range(32)]


def NonLinearTransformation(a):
    v = bytearray(a.to_bytes(16, 'big'))

    for i in range(16):
        v[i] = nonlinear[v[i]]

    return int.from_bytes(v, 'big')


def UnpackKey():

    s = '8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef'
    key = [0, 0]
    key[0] = bytearray.fromhex(s[:32])
    key[1] = bytearray.fromhex(s[32:])

    kkey[0] = int.from_bytes(key[0], 'big')
    kkey[1] = int.from_bytes(key[1], 'big')

    for i in range(1, 5):

        kkey[2 * i] = kkey[2 * i - 2]
        kkey[2 * i + 1] = kkey[2 * i - 1]
        for j in range(8):
            tmp = kkey[2*i] ^ C[j + 8*(i-1)]
            v = tmp.to_bytes(16, 'little')
            tmp = precomputed_LS[0][v[0]] ^ precomputed_LS[1][v[1]] ^ precomputed_LS[2][v[2]] ^ \
                precomputed_LS[3][v[3]] ^ precomputed_LS[4][v[4]] ^ precomputed_LS[5][v[5]] ^ \
                precomputed_LS[6][v[6]] ^ precomputed_LS[7][v[7]] ^ precomputed_LS[8][v[8]] ^ \
                precomputed_LS[9][v[9]] ^ precomputed_LS[10][v[10]] ^ precomputed_LS[11][v[11]] ^ \
                precomputed_LS[12][v[12]] ^ precomputed_LS[13][v[13]] ^ precomputed_LS[14][v[14]] ^ \
                precomputed_LS[15][v[15]] ^ kkey[2 * i + 1]
            kkey[2*i + 1] = kkey[2*i]
            kkey[2*i] = tmp


def Encode(input: bytearray):
    m = int.from_bytes(input, 'big')
    m ^= kkey[0]

    for i in range(9):
        tmp = m
        v = tmp.to_bytes(16, 'little')
        tmp = precomputed_LS[0][v[0]] ^ precomputed_LS[1][v[1]] ^ precomputed_LS[2][v[2]] ^ \
            precomputed_LS[3][v[3]] ^ precomputed_LS[4][v[4]] ^ precomputed_LS[5][v[5]] ^ \
            precomputed_LS[6][v[6]] ^ precomputed_LS[7][v[7]] ^ precomputed_LS[8][v[8]] ^ \
            precomputed_LS[9][v[9]] ^ precomputed_LS[10][v[10]] ^ precomputed_LS[11][v[11]] ^ \
            precomputed_LS[12][v[12]] ^ precomputed_LS[13][v[13]] ^ precomputed_LS[14][v[14]] ^ \
            precomputed_LS[15][v[15]] ^ kkey[i + 1]
        m = tmp
    return tmp.to_bytes(16, 'big')


def Decode(input: bytearray):
    m = int.from_bytes(input, 'big')
    m ^= kkey[9]

    for i in range(9):
        tmp = m
        
        v = tmp.to_bytes(16, 'little')
        tmp = precomputed_L_inv[0][v[0]] ^ precomputed_L_inv[1][v[1]] ^ precomputed_L_inv[2][v[2]] ^ \
            precomputed_L_inv[3][v[3]] ^ precomputed_L_inv[4][v[4]] ^ precomputed_L_inv[5][v[5]] ^ \
            precomputed_L_inv[6][v[6]] ^ precomputed_L_inv[7][v[7]] ^ precomputed_L_inv[8][v[8]] ^ \
            precomputed_L_inv[9][v[9]] ^ precomputed_L_inv[10][v[10]] ^ precomputed_L_inv[11][v[11]] ^ \
            precomputed_L_inv[12][v[12]] ^ precomputed_L_inv[13][v[13]] ^ precomputed_L_inv[14][v[14]] ^ \
            precomputed_L_inv[15][v[15]]
        tmp = S_inverse(tmp)
        tmp^= kkey[8 - i ]
        m = tmp
        
    return m.to_bytes(16, 'big')

def Decode1(input: bytearray):
    m = int.from_bytes(input, 'big')
    m ^= kkey[9]

    for i in range(9):
        tmp = m
        
        tmp = Linear_inverse(tmp)
        
        
        tmp = S_inverse(tmp)
        
        
        tmp^= kkey[8 - i]
        m = tmp
    return m.to_bytes(16, 'big')


class Kuznechik:
    def __init__(self, key) -> None:

        self.UnpackKey(key)

     

    key = [0 for j in range(10)]

    def UnpackKey(self, key):

        self.key[0] = int.from_bytes(key[:16], 'big')
        self.key[1] = int.from_bytes(key[16:], 'big')

        for i in range(1, 5):

            self.key[2 * i] = self.key[2 * i - 2]
            self.key[2 * i + 1] = self.key[2 * i - 1]
            for j in range(8):
                tmp = self.key[2*i] ^ C[j + 8*(i-1)]
                v = tmp.to_bytes(16, 'little')
                tmp = precomputed_LS[0][v[0]] ^ precomputed_LS[1][v[1]] ^ precomputed_LS[2][v[2]] ^ \
                    precomputed_LS[3][v[3]] ^ precomputed_LS[4][v[4]] ^ precomputed_LS[5][v[5]] ^ \
                    precomputed_LS[6][v[6]] ^ precomputed_LS[7][v[7]] ^ precomputed_LS[8][v[8]] ^ \
                    precomputed_LS[9][v[9]] ^ precomputed_LS[10][v[10]] ^ precomputed_LS[11][v[11]] ^ \
                    precomputed_LS[12][v[12]] ^ precomputed_LS[13][v[13]] ^ precomputed_LS[14][v[14]] ^ \
                    precomputed_LS[15][v[15]] ^ self.key[2 * i + 1]
                self.key[2*i + 1] = self.key[2*i]
                self.key[2*i] = tmp


    def Encode(self,input: bytearray):
        m = int.from_bytes(input, 'big')
        m ^= self.key[0]

        for i in range(9):
            v = m.to_bytes(16, 'little')
            m = precomputed_LS[0][v[0]] ^ precomputed_LS[1][v[1]] ^ precomputed_LS[2][v[2]] ^ \
                precomputed_LS[3][v[3]] ^ precomputed_LS[4][v[4]] ^ precomputed_LS[5][v[5]] ^ \
                precomputed_LS[6][v[6]] ^ precomputed_LS[7][v[7]] ^ precomputed_LS[8][v[8]] ^ \
                precomputed_LS[9][v[9]] ^ precomputed_LS[10][v[10]] ^ precomputed_LS[11][v[11]] ^ \
                precomputed_LS[12][v[12]] ^ precomputed_LS[13][v[13]] ^ precomputed_LS[14][v[14]] ^ \
                precomputed_LS[15][v[15]] ^ self.key[i + 1]
            
        return m.to_bytes(16, 'big')
    
    def Decode(self,input: bytearray):
        m = int.from_bytes(input, 'big')
        m ^= self.key[9]

        for i in range(9):
            tmp = m
            
            v = tmp.to_bytes(16, 'little')
            tmp = precomputed_L_inv[0][v[0]] ^ precomputed_L_inv[1][v[1]] ^ precomputed_L_inv[2][v[2]] ^ \
                precomputed_L_inv[3][v[3]] ^ precomputed_L_inv[4][v[4]] ^ precomputed_L_inv[5][v[5]] ^ \
                precomputed_L_inv[6][v[6]] ^ precomputed_L_inv[7][v[7]] ^ precomputed_L_inv[8][v[8]] ^ \
                precomputed_L_inv[9][v[9]] ^ precomputed_L_inv[10][v[10]] ^ precomputed_L_inv[11][v[11]] ^ \
                precomputed_L_inv[12][v[12]] ^ precomputed_L_inv[13][v[13]] ^ precomputed_L_inv[14][v[14]] ^ \
                precomputed_L_inv[15][v[15]]
            tmp = S_inverse(tmp)
            tmp^= self.key[8 - i ]
            m = tmp
            
        return m.to_bytes(16, 'big')
    
    def __lshift__(self, other):
        return self.Encode(other)


    def __rshift__(self, other):
        return self.Decode(other)
    


Prcompute_nonlinear_inverse()
Precompute_LS()
Precompute_LS_inv()

UnpackKey()



for i in kkey:
    prin(i)

input = bytearray.fromhex('1122334455667700ffeeddccbbaa9988')

mykey = bytearray.fromhex('8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef')

kuz = Kuznechik(mykey)


res = Encode(input)

res2 = kuz << input



print(binascii.hexlify(res))
print(binascii.hexlify(res2))

res3 = Decode(res)
res4 = kuz >> res2

print(binascii.hexlify(res3))
print(binascii.hexlify(res4))


start = time.time()


for i in range(65536):
    input = kuz << input

print("decode time: ",time.time() - start)

start = time.time()


for i in range(65536):
    input = kuz >> input

print("encode time: ",time.time() - start)