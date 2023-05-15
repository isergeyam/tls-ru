from tools.handshaketypes import *
from tools.handshakeparser import HandshakeParser

from cipher.TLSRu.KEG import KEG
from cipher.Streebog import StreebogHasher
from cipher.keyexpimp import KExpImp15

from record.record_protocol import RecordWriter, RecordReader
from cipher.P_50_1_113_2016.prf import PRF
from ec.curve_params import id_tc26_gost_3410_2012_512_paramSetC

test = True


class HandShakerServer:

    def __init__(self, reader, writer):
        self.PMSExp = None
        self.hr = RecordReader(reader)
        self.hw = RecordWriter(22, writer)
        self.parser = HandshakeParser()
        self.hasher = StreebogHasher(256)
        self.hasher_HM = StreebogHasher(256)
        self.rc = None
        self.rs = generate_random_with_time()
        if test:
            self.rs = bytearray.fromhex("""
                    933EA21E49C31BC3A3456165889684CA
                    A5576CE7924A24F58113808DBD9EF856
                    """)
        self.H = None
        self.curve = id_tc26_gost_3410_2012_512_paramSetC()
        self.ks = int.from_bytes(bytearray.fromhex("""
            12FD7A70067479A0F66C59F9A25534AD
            FBC7ABFD3CC72D79806F8B402601644B
            3005ED365A2D8989A8CCAE640D5FC08D
            D27DFBBFE137CF528E1AC6D445192E01
            """), 'big')
        self.Qs = self.curve.G * self.ks
        self.PS = None
        self.keph = None
        self.Keph = None
        self.KEG = KEG(self.curve)
        self.KExpMAC = None
        self.KExpENC = None
        self.MS = None

    async def receive(self):
        res = await self.parser(self.hr)
        assert self.hr.type == 22
        if res.variant_type != 0:
            self.hasher_HM << res.to_bytes()
        return res

    def send(self, value):
        self.hasher_HM << value
        self.hw.write(value)

    async def handshake(self):
        await self.reciverandom()

        self.sendrandom()
        self.sendcert()
        self.sendserverdone()
        await self.keyexchange()

        await self.unpack()

    def sendrandom(self):
        serverhello = ServerHello(self.rs)
        self.send(serverhello.to_bytes())

        self.H = self.hasher << self.rc << self.rs >> 0

    async def reciverandom(self):
        res = await self.receive()
        self.rc = res["random"].value
        if test:
            self.rc = bytearray.fromhex("""
            933EA21EC3802A561550EC78D6ED51AC
            2439D7E749C31BC3A3456165889684CA
            """)

    def sendcert(self):

        cert = bytearray.fromhex("""30 82 02 42 30 82
                    01 AE A0 03 02 01 02 02 01 01 30 0A 06 08 2A 85
                    03 07 01 01 03 03 30 42 31 2C 30 2A 06 09 2A 86
                    48 86 F7 0D 01 09 01 16 1D 74 6C 73 31 32 5F 73
                    65 72 76 65 72 35 31 32 43 40 63 72 79 70 74 6F
                    70 72 6F 2E 72 75 31 12 30 10 06 03 55 04 03 13
                    09 53 65 72 76 65 72 35 31 32 30 1E 17 0D 31 37 
                    30 35 32 35 30 39 32 35 31 38 5A 17 0D 33 30 30
                    35 30 31 30 39 32 35 31 38 5A 30 42 31 2C 30 2A
                    06 09 2A 86 48 86 F7 0D 01 09 01 16 1D 74 6C 73
                    31 32 5F 73 65 72 76 65 72 35 31 32 43 40 63 72
                    79 70 74 6F 70 72 6F 2E 72 75 31 12 30 10 06 03
                    55 04 03 13 09 53 65 72 76 65 72 35 31 32 30 81
                    AA 30 21 06 08 2A 85 03 07 01 01 01 02 30 15 06
                    09 2A 85 03 07 01 02 01 02 03 06 08 2A 85 03 07
                    01 01 02 03 03 81 84 00 04 81 80 3A 83 EB 1D F1
                    B8 39 FD E4 D2 5B B3 52 27 2D C2 10 33 7E 7C 0D
                    9F 23 4E 9B 3C 70 67 B2 06 97 7A 24 97 3E 13 C3
                    F6 9F CD 47 F4 8B 28 0A A3 E6 92 80 F5 3F 9B 66
                    63 65 C6 72 D9 9A 47 DA 89 45 F1 EA F4 11 7A 58
                    BE 6A B1 EB 67 D5 B3 E3 E1 78 BD E6 2B 61 1D A0
                    A7 01 41 CB 1C 5E 6A E6 DF F2 99 F2 13 04 3B B5
                    DD DF B1 04 2C 3A 7F 72 95 7C FC 0B B3 0A B2 9F
                    05 A1 60 4E 2D 50 36 5B E9 05 F3 A3 43 30 41 30
                    1D 06 03 55 1D 0E 04 16 04 14 87 9C C6 5A 0F 4A
                    89 CB 4A 58 49 DF 05 61 56 9B AA DC 11 69 30 0B
                    06 03 55 1D 0F 04 04 03 02 03 28 30 13 06 03 55
                    1D 25 04 0C 30 0A 06 08 2B 06 01 05 05 07 03 01
                    30 0A 06 08 2A 85 03 07 01 01 03 03 03 81 81 00
                    35 BE 38 51 EC B6 E9 2D 32 40 01 81 0F 8C 89 03
                    52 42 F4 05 46 9F 4C 4E CB 05 02 7C 57 E2 71 52
                    12 AF D7 CD BB 0C ED 7A 8B 4D 33 42 CC 50 1A BD
                    99 99 75 A5 8A DE 0E 58 4F CA 35 F5 2E 45 58 B7
                    31 1D 49 D0 A0 51 32 79 F7 39 37 1A F8 3C 5B C5
                    8B 36 6D FE FA 73 45 D5 03 17 86 7C 17 7A C8 4A
                    C0 7E E8 61 21 64 62 9A B7 BD C4 8A A0 F6 4A 74
                    1F E7 29 8E 82 C5 BF CE 86 72 02 9F 87 53 91 F7
                   """)
        cert = Certificate([cert])

        self.send(cert.to_bytes())

    async def keyexchange(self):

        res = await self.receive()

        self.PMSExp, self.Keph = get_data_from_keyexch(res, self.curve)

        tmp = self.KEG(self.ks, self.Keph, self.H)

        self.KExpMAC, self.KExpENC = tmp[:len(tmp) // 2], tmp[len(tmp) // 2:]

        self.PS = KExpImp15(self.KExpMAC, self.KExpENC, self.H[24: 24 + 8]).imp(self.PMSExp)

    def sendserverdone(self):

        self.send(ServerDone().to_bytes())

    async def unpack(self):
        label = bytearray()
        label.extend(map(ord, "extended master secret"))
        HM = ~self.hasher_HM
        if test:
            HM = bytearray.fromhex("""
            9D 64 0D D8 B2 54 6B 87 05 CC 3E 67 F3 BB 83 2F
            89 2A 5B D5 D4 5C A0 44 85 01 14 C2 E6 56 02 69
            """)
        self.MS = PRF(self.PS, 256).digest(label, HM, 48 * 8)

        label = bytearray()
        label.extend(map(ord, "key expansion"))
        tmp = PRF(self.MS, 256).digest(label, self.rs + self.rc, 16 * 8 * 9)

        self.KrMac, self.KwMac, self.KrEnc, self.KwEnc, self.IVr, self.IVw = split_key_material(tmp)

        HM = ~self.hasher_HM
        if test:
            HM = bytearray.fromhex("""
                            C9 A4 80 DA 29 6C DD 12 3E 9A EB 26 88 8B 86 19
                            EA 67 78 B7 23 FA A8 B2 DC 70 6A CB A5 AB AF 11
                            """)

        client_verify_data = PRF(self.MS, 256).digest("client finished", HM, 256)

        res = await self.hr.read(1)

        assert self.hr.type == 20 and res == bytearray.fromhex("01")

        self.hr.record_reader.set_keys(self.KrMac, self.KrEnc, self.IVr)

        res = await self.receive()

        assert client_verify_data == res["verify_data"].value

        self.hw.write_change_cypher_spec(bytearray.fromhex("01"))

        self.hw.record_writer.set_keys(self.KwMac, self.KwEnc, self.IVw)

        HM = ~self.hasher_HM
        if test:
            HM = bytearray.fromhex("""
                            4A 41 4C AD 20 F8 46 D8 F5 D1 05 26 10 A5 9D ED
                            6D 2B 1B B2 A8 9E 13 51 01 FC 9E 49 ED A8 0F B4
                            """)

        server_verify_data = PRF(self.MS, 256).digest("server finished", HM, 256)

        self.send(bytearray.fromhex("14 00 00 20") + server_verify_data)
