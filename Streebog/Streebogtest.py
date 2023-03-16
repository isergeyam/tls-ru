import unittest
import Streebog
import StreebogPrecompute
import binascii

def reverse64(b):
    for i in range(32):
        tmp = b[i]
        b[i] = b[63 - i] 
        b[63 - i] = tmp

def reverse32(b):
    for i in range(16):
        tmp = b[i]
        b[i] = b[31 - i] 
        b[31 - i] = tmp



class TestStreebog(unittest.TestCase):

    def test_empty(self):
        m = bytearray.fromhex('')
        str512exp = bytearray.fromhex('8e945da209aa869f0455928529bcae4679e9873ab707b55315f56ceb98bef0a7362f715528356ee83cda5f2aac4c6ad2ba3a715c1bcd81cb8e9f90bf4c1c1a8a')
        reverse64(str512exp)
        str256exp = bytearray.fromhex('3f539a213e97c802cc229d474c6aa32a825a360b2a933a949fd925208d9ce1bb')
        reverse32(str256exp)
        str512pre = StreebogPrecompute.streebog_hex(m)
        str512 = Streebog.streebog_hex(m)
        str256pre = StreebogPrecompute.streebog_hex(m, 256)
        str256 = Streebog.streebog_hex(m, 256)

        self.assertEqual(str512pre, str512exp)
        self.assertEqual(str512, str512exp)

        self.assertEqual(str256pre, str256exp)
        self.assertEqual(str256, str256exp)



    def test_short(self):
        m = bytearray.fromhex(
            '323130393837363534333231303938373635343332313039383736353433323130393837363534333231303938373635343332313039383736353433323130')

        str512 = Streebog.streebog_hex(m)
        str256 = Streebog.streebog_hex(m, 256)

        expected512 = bytearray.fromhex(
            '486f64c1917879417fef082b3381a4e211c324f074654c38823a7b76f830ad00fa1fbae42b1285c0352f227524bc9ab16254288dd6863dccd5b9f54a1ad0541b')

        expected256 = bytearray.fromhex(
            '00557be5e584fd52a449b16b0251d05d27f94ab76cbaa6da890b59d8ef1e159d')
        self.assertEqual(str512, expected512)
        self.assertEqual(str256, expected256)

    def test_long(self):
        m = bytearray.fromhex(
            'fbe2e5f0eee3c820fbeafaebef20fffbf0e1e0f0f520e0ed20e8ece0ebe5f0f2f120fff0eeec20f120faf2fee5e2202ce8f6f3ede220e8e6eee1e8f0f2d1202ce8f0f2e5e220e5d1')

        str512 = Streebog.streebog_hex(m)
        str256 = Streebog.streebog_hex(m, 256)

        expected512 = bytearray.fromhex(
            '28fbc9bada033b1460642bdcddb90c3fb3e56c497ccd0f62b8a2ad4935e85f037613966de4ee00531ae60f3b5a47f8dae06915d5f2f194996fcabf2622e6881e')

        expected256 = bytearray.fromhex(
            '508f7e553c06501d749a66fc28c6cac0b005746d97537fa85d9e40904efed29d')

        self.assertEqual(str512, expected512)
        self.assertEqual(str256, expected256)

    def test_short_pre(self):
        m = bytearray.fromhex(
            '323130393837363534333231303938373635343332313039383736353433323130393837363534333231303938373635343332313039383736353433323130')

        str512 = StreebogPrecompute.streebog_hex(m)
        str256 = StreebogPrecompute.streebog_hex(m, 256)

        expected512 = bytearray.fromhex(
            '486f64c1917879417fef082b3381a4e211c324f074654c38823a7b76f830ad00fa1fbae42b1285c0352f227524bc9ab16254288dd6863dccd5b9f54a1ad0541b')

        expected256 = bytearray.fromhex(
            '00557be5e584fd52a449b16b0251d05d27f94ab76cbaa6da890b59d8ef1e159d')
        self.assertEqual(str512, expected512)
        self.assertEqual(str256, expected256)

    def test_long_pre(self):
        m = bytearray.fromhex(
            'fbe2e5f0eee3c820fbeafaebef20fffbf0e1e0f0f520e0ed20e8ece0ebe5f0f2f120fff0eeec20f120faf2fee5e2202ce8f6f3ede220e8e6eee1e8f0f2d1202ce8f0f2e5e220e5d1')

        str512 = StreebogPrecompute.streebog_hex(m)
        str256 = StreebogPrecompute.streebog_hex(m, 256)

        expected512 = bytearray.fromhex(
            '28fbc9bada033b1460642bdcddb90c3fb3e56c497ccd0f62b8a2ad4935e85f037613966de4ee00531ae60f3b5a47f8dae06915d5f2f194996fcabf2622e6881e')

        expected256 = bytearray.fromhex(
            '508f7e553c06501d749a66fc28c6cac0b005746d97537fa85d9e40904efed29d')

        self.assertEqual(str512, expected512)
        self.assertEqual(str256, expected256)

    def test_big(self):
        test = bytearray(1024 * 1024 )

        StreebogPrecompute.streebog_hex(test)

if __name__ == '__main__':
    unittest.main()
