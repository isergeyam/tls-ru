from tools.handshaketypes import *
from tools.handshakeparser import HandshakeParser

from cipher.TLSRu.KEG import KEG
from cipher.Streebog import StreebogHasher
from cipher.keyexpimp import KExpImp15
from cipher.P_50_1_113_2016.prf import PRF

from record.record_protocol import RecordWriter, RecordReader

test = False


class HandShakerClient:

    def __init__(self, reader, writer):
        self.IVr = None
        self.IVw = None
        self.KrMac = None
        self.KrEnc = None
        self.KwMac = None
        self.KwEnc = None
        self.hr = RecordReader(reader)
        self.hw = RecordWriter(22, writer)
        self.parser = HandshakeParser()
        self.hasher = StreebogHasher(256)
        self.hasher_HM = StreebogHasher(256)
        self.rc = generate_random_with_time()
        if test:
            self.rc = bytearray.fromhex(
                """
                933EA21EC3802A561550EC78D6ED51AC
                2439D7E749C31BC3A3456165889684CA
                """)

        self.rs = None
        self.H = None
        self.curve = None
        self.Qs = None
        self.PS = generate_random(32)
        if test:
            self.PS = bytearray.fromhex(
                """
                A5 57 6C E7 92 4A 24 F5 81 13 80 8D BD 9E F8 56
                F5 BD C3 B1 83 CE 5D AD CA 36 A5 3A A0 77 65 1D
                """)
        self.keph = None

        self.kephtest = int.from_bytes(bytearray.fromhex("""
            150ACD11B66DD695AD18418FA7A2DC63
            6B7E29DCA24536AABC826EE3175BB1FA
            DC3AA0D01D3092E120B0FCF7EB872F4B
            7E26EA17849D689222A48CF95A6E4831
            """), 'big')
        self.Keph = None
        self.KEG = None
        self.KExpMAC = None
        self.KExpENC = None
        self.PMSExp = None
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
        self.sendrandom()
        await self.reciverandom()
        await self.recivecert()
        await self.receiveserverdone()
        self.keyexchange()

        await self.unpack()

    def sendrandom(self):
        clienthello = ClientHello(self.rc)
        self.send(clienthello.to_bytes())

    async def reciverandom(self):
        res = await self.receive()

        self.rs = res["random"].value
        if test:
            self.rs = bytearray.fromhex("""
            933EA21E49C31BC3A3456165889684CA
            A5576CE7924A24F58113808DBD9EF856
            """)

        self.H = self.hasher << self.rc << self.rs >> 0

    async def recivecert(self):
        res = await self.receive()
        print(res)
        self.curve = get_curve_from_cert(res)
        self.Qs = get_point_from_cert(res, self.curve)
        self.KEG = KEG(self.curve)

    def keyexchange(self):

        self.keph = self.curve.random()
        if test:
            self.keph = self.kephtest
        self.Keph = self.curve.G * self.keph

        tmp = self.KEG(self.keph, self.Qs, self.H)

        self.KExpMAC, self.KExpENC = tmp[:len(tmp) // 2], tmp[len(tmp) // 2:]

        self.PMSExp = KExpImp15(self.KExpMAC, self.KExpENC, self.H[24: 24 + 8]).exp(self.PS)

        self.send(KeyEschange(self.PMSExp, self.Keph, self.curve))

    async def receiveserverdone(self):
        res = await self.receive()
        assert res.variant_type == 14

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
        self.KwMac, self.KrMac, self.KwEnc, self.KrEnc, self.IVw, self.IVr = split_key_material(tmp)

        self.hw.write_change_cypher_spec(bytearray.fromhex("01"))

        self.hw.record_writer.set_keys(self.KwMac, self.KwEnc, self.IVw)

        HM = ~self.hasher_HM
        if test:
            HM = bytearray.fromhex("""
                    C9 A4 80 DA 29 6C DD 12 3E 9A EB 26 88 8B 86 19
                    EA 67 78 B7 23 FA A8 B2 DC 70 6A CB A5 AB AF 11
                    """)

        client_verify_data = PRF(self.MS, 256).digest("client finished", HM, 256)

        self.send(bytearray.fromhex("14 00 00 20") + client_verify_data)

        HM = ~self.hasher_HM
        if test:
            HM = bytearray.fromhex("""
                                    4A 41 4C AD 20 F8 46 D8 F5 D1 05 26 10 A5 9D ED
                                    6D 2B 1B B2 A8 9E 13 51 01 FC 9E 49 ED A8 0F B4
                                    """)

        server_verify_data = PRF(self.MS, 256).digest("server finished", HM, 256)

        res = await self.hr.read(1)

        assert self.hr.type == 20 and res == bytearray.fromhex("01")

        self.hr.record_reader.set_keys(self.KrMac, self.KrEnc, self.IVr)

        res = await self.receive()

        assert server_verify_data == res["verify_data"].value
