import unittest
import Streebog
import StreebogPrecompute
import binascii


def reverse(m):
    for i in range(len(m)//2):
        tmp = m[i]
        m[i] = m[len(m)-1 - i]
        m[len(m)-1 - i] = tmp


class TestStreebog(unittest.TestCase):

    def test_big_zero(self):
        test = bytearray(1024 * 1024)
        res = StreebogPrecompute.streebog(test)
        print(binascii.hexlify(res))

    def test_big_ff(self):
        test = bytearray.fromhex('ff'*(1024*1024))
        res = StreebogPrecompute.streebog(test)
        print(binascii.hexlify(res))

    def check_hex_input_from_gost(self, input,  exp256, exp512):
        byte_array_512_exp = bytearray.fromhex(
            exp512)
        byte_array_256_exp = bytearray.fromhex(
            exp256)
        byte_array_input = bytearray.fromhex(
            input)

        reverse(byte_array_256_exp)
        reverse(byte_array_512_exp)
        reverse(byte_array_input)

        byte_array_512_res = StreebogPrecompute.streebog(
            byte_array_input, 512)
        byte_array_256_res = StreebogPrecompute.streebog(
            byte_array_input, 256)

        self.assertEqual(byte_array_512_res, byte_array_512_exp)
        self.assertEqual(byte_array_256_res, byte_array_256_exp)

    def check_hex_input(self, input, exp256, exp512):
        byte_array_512_exp = bytearray.fromhex(
            exp512)
        byte_array_256_exp = bytearray.fromhex(
            exp256)
        byte_array_input = bytearray.fromhex(
            input)

        byte_array_512_res = StreebogPrecompute.streebog(
            byte_array_input, 512)
        byte_array_256_res = StreebogPrecompute.streebog(
            byte_array_input, 256)

        self.assertEqual(byte_array_512_res, byte_array_512_exp)
        self.assertEqual(byte_array_256_res, byte_array_256_exp)

    def check_string_input(self, input, exp256, exp512):
        byte_array_512_exp = bytearray.fromhex(
            exp512)
        byte_array_256_exp = bytearray.fromhex(
            exp256)
        byte_array_input = bytearray()
        byte_array_input.extend(map(ord, input))

        byte_array_512_res = StreebogPrecompute.streebog(
            byte_array_input, 512)
        byte_array_256_res = StreebogPrecompute.streebog(
            byte_array_input, 256)

        self.assertEqual(byte_array_512_res, byte_array_512_exp)
        self.assertEqual(byte_array_256_res, byte_array_256_exp)

    def check_bytes_input(self, input, exp256, exp512):
        byte_array_512_exp = bytearray.fromhex(
            exp512)
        byte_array_256_exp = bytearray.fromhex(
            exp256)
        byte_array_input = input

        byte_array_512_res = StreebogPrecompute.streebog(
            byte_array_input, 512)
        byte_array_256_res = StreebogPrecompute.streebog(
            byte_array_input, 256)

        self.assertEqual(byte_array_512_res, byte_array_512_exp)
        self.assertEqual(byte_array_256_res, byte_array_256_exp)

    def test_gost(self):
        self.check_hex_input_from_gost(
            '323130393837363534333231303938373635343332313039383736353433323130393837363534333231303938373635343332313039383736353433323130',
            '00557be5e584fd52a449b16b0251d05d27f94ab76cbaa6da890b59d8ef1e159d',
            '486f64c1917879417fef082b3381a4e211c324f074654c38823a7b76f830ad00fa1fbae42b1285c0352f227524bc9ab16254288dd6863dccd5b9f54a1ad0541b')

        self.check_hex_input_from_gost(
            'fbe2e5f0eee3c820fbeafaebef20fffbf0e1e0f0f520e0ed20e8ece0ebe5f0f2f120fff0eeec20f120faf2fee5e2202ce8f6f3ede220e8e6eee1e8f0f2d1202ce8f0f2e5e220e5d1',
            '508f7e553c06501d749a66fc28c6cac0b005746d97537fa85d9e40904efed29d',
            '28fbc9bada033b1460642bdcddb90c3fb3e56c497ccd0f62b8a2ad4935e85f037613966de4ee00531ae60f3b5a47f8dae06915d5f2f194996fcabf2622e6881e'
        )

        self.check_hex_input(
            '',
            '3f539a213e97c802cc229d474c6aa32a825a360b2a933a949fd925208d9ce1bb',
            '8e945da209aa869f0455928529bcae4679e9873ab707b55315f56ceb98bef0a7362f715528356ee83cda5f2aac4c6ad2ba3a715c1bcd81cb8e9f90bf4c1c1a8a'
        )

        self.check_string_input(
            '',
            '3f539a213e97c802cc229d474c6aa32a825a360b2a933a949fd925208d9ce1bb',
            '8e945da209aa869f0455928529bcae4679e9873ab707b55315f56ceb98bef0a7362f715528356ee83cda5f2aac4c6ad2ba3a715c1bcd81cb8e9f90bf4c1c1a8a'
        )

        self.check_string_input(
            'The quick brown fox jumps over the lazy dog',
            '3e7dea7f2384b6c5a3d0e24aaa29c05e89ddd762145030ec22c71a6db8b2c1f4',
            'd2b793a0bb6cb5904828b5b6dcfb443bb8f33efc06ad09368878ae4cdc8245b97e60802469bed1e7c21a64ff0b179a6a1e0bb74d92965450a0adab69162c00fe'
        )

        self.check_string_input(
            'The quick brown fox jumps over the lazy dog.',
            '36816a824dcbe7d6171aa58500741f2ea2757ae2e1784ab72c5c3c6c198d71da',
            'fe0c42f267d921f940faa72bd9fcf84f9f1bd7e9d055e9816e4c2ace1ec83be82d2957cd59b86e123d8f5adee80b3ca08a017599a9fc1a14d940cf87c77df070'
        )

        self.check_bytes_input(
            bytearray(0),
            '3f539a213e97c802cc229d474c6aa32a825a360b2a933a949fd925208d9ce1bb',
            '8e945da209aa869f0455928529bcae4679e9873ab707b55315f56ceb98bef0a7362f715528356ee83cda5f2aac4c6ad2ba3a715c1bcd81cb8e9f90bf4c1c1a8a'
        )

        self.check_bytes_input(bytearray(64),
                               'df1fda9ce83191390537358031db2ecaa6aa54cd0eda241dc107105e13636b95',
                               'b0fd29ac1b0df441769ff3fdb8dc564df67721d6ac06fb28ceffb7bbaa7948c6c014ac999235b58cb26fb60fb112a145d7b4ade9ae566bf2611402c552d20db7')

        self.check_hex_input('36373435323330313e3f3c3d3a3b383926272425222320212e2f2c2d2a2b282936363636363636363636363636363636363636363636363636363636363636360126bdb87800af214341456563780100',
                             '612fbfc167a28e5554794a692ef508394fee9a8a3ba57ae919f44b62a2a361d4',
                             '0d5a45fe1a3af3d8b8de724d6e03de7bfaeb479ceaf4b9dae658effb30d09287081164767218d4db508f6fd1b355ab0e47d2a1fefcc513f779ac47a723b6fc92')

    def check_single(self, input, exp512, exp256):
        byte_array_512_exp = bytearray.fromhex(
            exp512)
        byte_array_256_exp = bytearray.fromhex(
            exp256)
        byte_array_input = bytearray.fromhex(
            input)

        byte_array_512_res = StreebogPrecompute.streebog(
            byte_array_input, 512)
        byte_array_256_res = StreebogPrecompute.streebog(
            byte_array_input, 256)

        self.assertEqual(byte_array_512_res, byte_array_512_exp)
        self.assertEqual(byte_array_256_res, byte_array_256_exp)

    inputs = []
    results256 = []
    results512 = []


if __name__ == '__main__':
    unittest.main()
