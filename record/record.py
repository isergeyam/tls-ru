from math import ceil
import asyncio
import os
from contextlib import contextmanager
import sys
import typing as tp

from TLSTree import *
from cipher import *
from Kuznechik import Kuznechik


@contextmanager
def exception_guard(message_on_exit: str = 'exit'):
    try:
        yield None
    finally:
        print(message_on_exit)
        return True  # indicates that exception was gracefully handled


class Record:
    def __init__(self):
        self.type = 0
        self.version = 0x0303
        self.lengths = []
        self.fragments = []

        self.cipher = False
        self.Kmac = None
        self.Kenc = None
        self.IV = None
        # по идее ключи и IV должны откуда то приходить

        self.TLSPlaintexts = []
        self.TLSCiphertexts = []

    def create_records(self, type: int, message: bytes):
        self.type = type
        n = ceil(len(message) / 2 ** 14)
        for i in range(n):
            self.fragments.append(message[i * 2 ** 14: (i + 1) * 2 ** 14])
        for i in self.fragments:
            self.lengths.append(len(i))

        if not self.cipher:
            for i in range(len(self.fragments)):
                self.TLSPlaintexts.append(bytearray(self.type.to_bytes(1, 'big')) +
                                          bytearray(self.version.to_bytes(2, 'big')) +
                                          bytearray(self.lengths[i].to_bytes(2, 'big')) +
                                          self.fragments[i]
                                          )
        else:
            tree1 = newTLSTreeKuznechik(self.Kmac)
            tree2 = newTLSTreeKuznechik(self.Kenc)
            for i in range(len(self.fragments)):
                MACData = (bytearray(i.to_bytes(8, 'big')) +
                           bytearray(self.type.to_bytes(1, 'big')) +
                           bytearray(self.version.to_bytes(2, 'big')) +
                           bytearray(self.lengths[i].to_bytes(2, 'big')) +
                           self.fragments[i]
                           )

                Kmac = tree1(i)
                omac = OMAC(Kuznechik(Kmac), 128)
                RecMac = omac.mac(MACData)

                Kenc = tree2(i)
                EncData = self.fragments[i] + RecMac
                IV = bytearray(((int.from_bytes(self.IV, 'big') + i) % pow(2, 64)).to_bytes(8, 'big'))
                RecEnc = CtrAcpkm(Kuznechik(Kenc), 256, 128).encode(IV, EncData)

                self.TLSCiphertexts.append(bytearray(self.type.to_bytes(1, 'big')) +
                                           bytearray(self.version.to_bytes(2, 'big')) +
                                           bytearray(self.lengths[i].to_bytes(2, 'big')) +
                                           RecEnc
                                           )

    def send_records(self, writer: asyncio.StreamWriter):
        for record in self.TLSPlaintexts:
            writer.write(record)

    async def read_records(self, reader: asyncio.StreamReader) -> tp.AsyncIterator[bytes]:
        try:
            while True:
                type = int.from_bytes(await reader.readexactly(1), 'big')
                assert type == 0x23
                version = int.from_bytes(await reader.readexactly(2), 'big')
                assert version == 0x0303
                length = int.from_bytes(await reader.readexactly(2), 'big')
                fragment = await reader.readexactly(length)
                yield fragment
        except:
            pass


message_len = 100 * 1024 * 1024
my_message = os.urandom(message_len)

global server
global server_started


async def handle_read_records(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    global server
    rec = Record()
    message = bytearray()
    async for fragment in rec.read_records(reader):
        message += fragment
    print(f"Received {len(message)} fragment")
    assert message == my_message
    server.close()


async def start_server():
    global server
    global server_started
    server = await asyncio.start_server(handle_read_records, 'localhost', 8888)
    server_started.set()

    addrs = ', '.join(str(sock.getsockname()) for sock in server.sockets)
    print(f'Serving on {addrs}')

    async with server:
        await server.serve_forever()


async def main():
    global server_started
    server_started = asyncio.Event()
    server = asyncio.create_task(start_server())
    await server_started.wait()
    rec = Record()
    rec.create_records(0x23, my_message)
    reader, writer = await asyncio.open_connection('localhost', 8888)
    rec.send_records(writer)
    writer.close()
    await server


if __name__ == '__main__':
    with exception_guard('shutdown server'):
        asyncio.run(main())
