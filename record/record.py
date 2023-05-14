import io
from math import ceil, floor
import asyncio
import os
from contextlib import contextmanager
import typing as tp

from cipher.TLSRu.TLSTree import *
from cipher import *
from Kuznechik import Kuznechik

from tools import append_buffer
from traceback import print_exc


@contextmanager
def exception_guard(message_on_exit: str = 'exit'):
    try:
        yield None
    finally:
        print(message_on_exit)
        return True  # indicates that exception was gracefully handled


global mac_data


class Record:
    def __init__(self):
        self.type = 0
        self.version = 0x0303
        self.seqnum = 0

        self.cipher = False
        self.Kmac = None
        self.Kenc = None
        self.IV = None
        self.mac_tls_tree = None
        self.enc_tls_tree = None
        # по идее ключи и IV должны откуда то приходить

    def set_keys(self, Kmac, Kenc, IV):
        self.Kmac = Kmac
        self.Kenc = Kenc
        self.IV = IV
        self.mac_tls_tree = newTLSTreeKuznechik(Kmac)
        self.enc_tls_tree = newTLSTreeKuznechik(Kenc)
        self.cipher = True
        self.seqnum = 0

    def mac_data(self, length, fragment):
        MACData = (bytearray(self.seqnum.to_bytes(8, 'big')) +
                   bytearray(self.type.to_bytes(1, 'big')) +
                   bytearray(self.version.to_bytes(2, 'big')) +
                   bytearray(length.to_bytes(2, 'big')) +
                   fragment
                   )
        return MACData

    def write_records(self, type: int, message: bytes, writer: asyncio.StreamWriter):
        self.type = type
        n = ceil(len(message) / 2 ** 14)
        if not self.cipher:
            for i in range(n):
                fragment = message[i * 2 ** 14: (i + 1) * 2 ** 14]
                length = len(fragment)
                writer.write(bytearray(self.type.to_bytes(1, 'big')) +
                             bytearray(self.version.to_bytes(2, 'big')) +
                             bytearray(length.to_bytes(2, 'big')) +
                             fragment)
                self.seqnum += 1
        else:
            for i in range(n):
                fragment = message[i * 2 ** 14: (i + 1) * 2 ** 14]
                length = len(fragment)
                global mac_data
                MACData = self.mac_data(length, fragment)
                mac_data = MACData

                Kmac = self.mac_tls_tree(self.seqnum)
                omac = OMAC(Kuznechik(Kmac), 128)
                RecMac = omac.mac(MACData)

                Kenc = self.enc_tls_tree(self.seqnum)
                EncData = fragment + RecMac
                IV = bytearray(((int.from_bytes(self.IV, 'big') + self.seqnum) % pow(2, 64)).to_bytes(8, 'big'))
                RecEnc = CtrAcpkm(Kuznechik(Kenc), 256, 128).encode(IV, EncData)
                length = len(RecEnc)

                writer.write(bytearray(self.type.to_bytes(1, 'big')) +
                             bytearray(self.version.to_bytes(2, 'big')) +
                             bytearray(length.to_bytes(2, 'big')) +
                             RecEnc
                             )
                self.seqnum += 1

    async def read_record(self, reader: asyncio.StreamReader) -> (int, bytes):
        try:
            type = int.from_bytes(await reader.readexactly(1), 'big')
            self.type = type
            # assert type == 0x23
            version = int.from_bytes(await reader.readexactly(2), 'big')
            assert version == 0x0303
            length = int.from_bytes(await reader.readexactly(2), 'big')
            fragment = await reader.readexactly(length)
            if not self.cipher:
                self.seqnum += 1
                return type, fragment
            else:
                Kmac = self.mac_tls_tree(self.seqnum)
                omac = OMAC(Kuznechik(Kmac), 128)
                Kenc = self.enc_tls_tree(self.seqnum)
                IV = bytearray(((int.from_bytes(self.IV, 'big') + self.seqnum) % pow(2, 64)).to_bytes(8, 'big'))
                RecEnc = CtrAcpkm(Kuznechik(Kenc), 256, 128).decode(IV, fragment)
                fragment = RecEnc[:-16]
                length = len(fragment)
                mac = RecEnc[-16:]
                MACData = self.mac_data(length, fragment)
                in_mac = omac.mac(MACData)
                assert in_mac == mac
                self.seqnum += 1
                return type, fragment

        except:
            # print_exc()
            return 0, bytes()


class RecordReaderWrapper:
    def __init__(self, read_buffer, record_type):
        self.read_buffer = read_buffer
        self.record_type = record_type
        self.pos = 0

    async def read(self, size):
        self.pos += size
        return await self.read_buffer(self.record_type, size)

    def tell(self):
        return self.pos


class RecordWriterWrapper:
    def __init__(self, record_writer, record_type):
        self.record_writer = record_writer
        self.record_type = record_type

    def write(self, message):
        self.record_writer(self.record_type, message)


class RecordAlternative:

    def __init__(self, reader, writer):
        self.reader = reader
        self.writer = writer
        self.handshake_buffer = io.BytesIO()
        self.appdata_buffer = io.BytesIO()
        self.version = 0x0303
        self.cipher = False
        self.input = []
        self.output = []

    async def read_buffer(self, record_type, size):
        result = bytearray()
        current = 0
        if record_type == 22:
            while current != size:
                result.extend(self.handshake_buffer.read(size))
                if len(result) == current:
                    await self.read_record()
                current = len(result)
        if record_type == 23:
            while current != size:
                result.extend(self.appdata_buffer.read(size))
                if len(result) == current:
                    await self.read_record()
                current = len(result)
        return result

    async def read_record(self):
        record_type = int.from_bytes(await self.reader.readexactly(1), 'big')
        version = int.from_bytes(await self.reader.readexactly(2), 'big')
        assert version == 0x0303
        length = int.from_bytes(await self.reader.readexactly(2), 'big')
        fragment = await self.reader.readexactly(length)
        if record_type == 22:
            append_buffer(self.handshake_buffer, fragment)

        if record_type == 23:
            append_buffer(self.appdata_buffer, fragment)

    def record_writer(self, record_type, message):
        n = floor(len(message) / 2 ** 14)
        for i in range(n):
            self.send_fragment(record_type, message[i * 2 ** 14: (i + 1) * 2 ** 14])
        if len(message) % 2 ** 14:
            self.send_fragment(record_type, message[n * 2 ** 14:])

    def send_fragment(self, record_type, fragment):
        if not self.cipher:
            plain = bytearray(record_type.to_bytes(1, 'big')) + \
                    bytearray(self.version.to_bytes(2, 'big')) + \
                    bytearray(len(fragment).to_bytes(2, 'big')) + \
                    fragment
            self.output.append(plain)
            self.writer.write(plain)

    def handshaker(self):
        return RecordReaderWrapper(self.read_buffer, 22), RecordWriterWrapper(self.record_writer, 22)

    def appdata_rw(self):
        return RecordReaderWrapper(self.read_buffer, 23), RecordWriterWrapper(self.record_writer, 23)


num_messages = 3
message_len = 1024 * 1024
my_messages = [os.urandom(message_len) for i in range(num_messages)]

global server
global server_started
K = bytearray.fromhex("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")
IV = bytearray.fromhex('12 34 56 78 90 AB CE F0')


async def handle_read_records(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    global server
    idx = 0
    rec = Record()
    rec.set_keys(K, K, IV)
    message = bytearray()
    while True:
        type, fragment = await rec.read_record(reader)
        message += fragment
        if len(message) == message_len:
            print(f"Received {len(message)} fragment")
            assert message == my_messages[idx]
            message = bytearray()
            idx += 1
            if idx == num_messages:
                server.close()
                return


async def start_server():
    global server
    global server_started
    server = await asyncio.start_server(handle_read_records, 'localhost', 8888)
    server_started.set()

    addrs = ', '.join(str(sock.getsockname()) for sock in server.sockets)
    print(f'Serving on {addrs}')

    async with server:
        await server.serve_forever()


async def client():
    rec = Record()
    rec.set_keys(K, K, IV)
    reader, writer = await asyncio.open_connection('localhost', 8888)
    for i in range(num_messages):
        rec.write_records(0x23, my_messages[i], writer)
    writer.close()


async def main():
    global server_started
    global idx
    server_started = asyncio.Event()
    idx = 0
    server = asyncio.create_task(start_server())
    await server_started.wait()
    await client()
    await server


if __name__ == '__main__':
    with exception_guard('shutdown server'):
        asyncio.run(main())
