import asyncio
from tools.handshaketypes import *
from tools.handshakeparser import HandshakeParser

test = False


class HandShakerClient:

    def __init__(self, record):
        self.hr, self.hw = record.handshaker()
        self.parser = HandshakeParser()
        self.rc = None
        self.rs = None
        self.curve = None
        self.QS = None

    async def handshake(self):
        self.sendrandom()
        await self.reciverandom()

    def sendrandom(self):
        self.rc = generate_random()
        if test:
            self.rc = bytearray(32)
        clienthello = ClientHello(self.rc)
        self.hw.write(clienthello.to_bytes())

    async def reciverandom(self):
        res = await self.parser(self.hr)
        self.rs = res["random"].value

    async def recivecert(self):
        res = await self.parser(self.hr)
        self.curve = get_curve_from_cert(res)
        self.QS = get_point_from_cert(res, self.curve)
