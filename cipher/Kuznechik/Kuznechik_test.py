import unittest
import time
from cipher import Kuznechik


def reverse(m):
    for i in range(len(m)//2):
        tmp = m[i]
        m[i] = m[len(m)-1 - i]
        m[len(m)-1 - i] = tmp


class TestKuznechik(unittest.TestCase):

    def test_big_zero(self):
        kuz = Kuznechik.Kuznechik(bytearray(0))
        input = bytearray(16)
        start = time.time()
        for i in range(65536):
            input = kuz << input

        print("decode time: ", time.time() - start)

        start = time.time()

        for i in range(65536):
            input = kuz >> input

        print("encode time: ", time.time() - start)

        self.assertEqual(input, bytearray(16))

    def test_gost(self):
        input = bytearray.fromhex('1122334455667700ffeeddccbbaa9988')

        mykey = bytearray.fromhex(
            '8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef')

        exp = bytearray.fromhex('7f679d90bebc24305a468d42b9d4edcd')

        kuz = Kuznechik.Kuznechik(mykey)

        res = kuz << input

        res_inverse = kuz >> res

        self.assertEqual(res, exp)
        self.assertEqual(res_inverse, input)


if __name__ == '__main__':
    unittest.main()
