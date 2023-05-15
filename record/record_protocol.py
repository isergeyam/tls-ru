import io
from math import ceil, floor
import asyncio
import os
from contextlib import contextmanager

from cipher.TLSRu.TLSTree import *
from cipher import *
from cipher.Kuznechik import Kuznechik

from tools import append_buffer


@contextmanager
def exception_guard(message_on_exit: str = 'exit'):
    try:
        yield None
    finally:
        print(message_on_exit)
        return True  # indicates that exception was gracefully handled


class RecordBase:
    def __init__(self):
        self.version = 0x0303
        self.seqnum = 0

        self.cipher = False
        self.Kmac = None
        self.Kenc = None
        self.IV = None
        self.mac_kaznechik_on_tree = None
        self.enc_kaznechik_on_tree = None

    def mac_data(self, tp, length, fragment):
        data = (bytearray(self.seqnum.to_bytes(8, 'big')) +
                bytearray(tp.to_bytes(1, 'big')) +
                bytearray(self.version.to_bytes(2, 'big')) +
                bytearray(length.to_bytes(2, 'big')) +
                fragment
                )
        return data

    def set_keys(self, Kmac, Kenc, IV):
        self.Kmac = Kmac
        self.Kenc = Kenc
        self.IV = IV
        self.mac_kaznechik_on_tree = KuznechikOnTree(Kmac)
        self.enc_kaznechik_on_tree = KuznechikOnTree(Kenc)
        self.cipher = True
        self.seqnum = 0


class RecordReaderSimple(RecordBase):
    def __init__(self):
        super().__init__()

    async def read_record(self, reader: asyncio.StreamReader) -> (int, bytes):
        try:
            record_type = int.from_bytes(await reader.readexactly(1), 'big')
            # assert type == 0x23
            version = int.from_bytes(await reader.readexactly(2), 'big')
            assert version == 0x0303
            length = int.from_bytes(await reader.readexactly(2), 'big')
            fragment = await reader.readexactly(length)
            if not self.cipher:
                self.seqnum += 1
                return record_type, fragment
            else:
                omac = OMAC(self.mac_kaznechik_on_tree(self.seqnum), 128)
                IV = bytearray(((int.from_bytes(self.IV, 'big') + self.seqnum) % pow(2, 64)).to_bytes(8, 'big'))
                RecEnc = CtrAcpkm(self.enc_kaznechik_on_tree(self.seqnum), 256, 128).decode(IV, fragment)
                fragment = RecEnc[:-16]
                length = len(fragment)
                mac = RecEnc[-16:]
                MACData = self.mac_data(record_type, length, fragment)
                in_mac = omac.mac(MACData)
                assert in_mac == mac
                self.seqnum += 1
                return record_type, fragment

        except:
            # print_exc()
            return 0, bytes()


class RecordWriterSimple(RecordBase):
    def __init__(self):
        super().__init__()

    def write_records(self, record_type: int, message: bytes, writer: asyncio.StreamWriter):
        n = ceil(len(message) / 2 ** 14)
        if not self.cipher:
            for i in range(n):
                fragment = message[i * 2 ** 14: (i + 1) * 2 ** 14]
                length = len(fragment)
                writer.write(bytearray(record_type.to_bytes(1, 'big')) +
                             bytearray(self.version.to_bytes(2, 'big')) +
                             bytearray(length.to_bytes(2, 'big')) +
                             fragment)
                self.seqnum += 1
        else:
            for i in range(n):
                fragment = message[i * 2 ** 14: (i + 1) * 2 ** 14]
                length = len(fragment)
                MACData = self.mac_data(record_type, length, fragment)

                omac = OMAC(self.mac_kaznechik_on_tree(self.seqnum), 128)
                RecMac = omac.mac(MACData)

                EncData = fragment + RecMac
                IV = bytearray(((int.from_bytes(self.IV, 'big') + self.seqnum) % pow(2, 64)).to_bytes(8, 'big'))
                RecEnc = CtrAcpkm(self.enc_kaznechik_on_tree(self.seqnum), 256, 128).encode(IV, EncData)
                length = len(RecEnc)

                writer.write(bytearray(record_type.to_bytes(1, 'big')) +
                             bytearray(self.version.to_bytes(2, 'big')) +
                             bytearray(length.to_bytes(2, 'big')) +
                             RecEnc
                             )
                self.seqnum += 1


class RecordReader:
    def __init__(self, io_reader: asyncio.StreamReader):
        self.record_reader = RecordReaderSimple()
        self.pos = 0
        self.type = None
        self.cur_buffer = bytearray()
        self.io_reader = io_reader

    async def read(self, size):
        self.pos += size
        buf = bytearray()
        while size != 0:
            if size > len(self.cur_buffer):
                size -= len(self.cur_buffer)
                buf += self.cur_buffer
                self.type, self.cur_buffer = await self.record_reader.read_record(self.io_reader)
            else:
                buf += self.cur_buffer[:size]
                self.cur_buffer = self.cur_buffer[size:]
                size = 0
        return buf

    def tell(self):
        return self.pos

    def get_type(self):
        return self.type


class RecordWriter:
    def __init__(self, record_type: int, io_writer: asyncio.StreamWriter):
        self.record_type = record_type
        self.io_writer = io_writer
        self.record_writer = RecordWriterSimple()

    def write(self, message):
        self.record_writer.write_records(self.record_type, message, self.io_writer)


num_messages = 3
message_len = 1024 * 1024
my_messages = [os.urandom(message_len) for i in range(num_messages)]

global server
global server_started
K = bytearray.fromhex("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")
IV = bytearray.fromhex('12 34 56 78 90 AB CE F0')


async def handle_read_records(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    global server
    rec = RecordReader(reader)
    rec.record_reader.set_keys(K, K, IV)
    for expected_message in my_messages:
        message = await rec.read(message_len)
        assert message == expected_message
        print("Received message")
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


async def client():
    reader, writer = await asyncio.open_connection('localhost', 8888)
    rec = RecordWriter(0x23, writer)
    rec.record_writer.set_keys(K, K, IV)
    for message in my_messages:
        rec.write(message)
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
