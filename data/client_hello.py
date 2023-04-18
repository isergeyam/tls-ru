from extension import *
import asyncio
from async_io import StreamReader
from contextlib import contextmanager
import os


class ClientHello(object):
    def __init__(self):
        pass

    async def deserialize(self, _reader: asyncio.StreamReader) -> int:
        reader = StreamReader(_reader)
        version = await reader.read_int(2)
        assert version == 0x0303
        self.random = await reader.readexactly(32)
        length = await reader.read_int(1)
        self.session_id = await reader.readexactly(length)
        length = await reader.read_int(2)
        self.cipher_suites = []
        for i in range(length // 2):
            self.cipher_suites.append(await reader.read_int(2))
        length = await reader.read_int(1)
        assert length == 1
        assert b'\0' == await reader.readexactly(1)
        length = await reader.read_int(2)
        self.extensions = []
        read = 0
        while read < length:
            extension = Extension()
            read += await extension.deserialize(_reader)
            self.extensions.append(extension)
        return reader.count

    def __eq__(self, other):
        if not isinstance(other, ClientHello):
            return False
        return self.random == other.random and self.session_id == other.session_id \
            and self.cipher_suites == other.cipher_suites and self.extensions == other.extensions


async def reader_from_buffer(buf: bytes):
    r, w = os.pipe()
    os.write(w, buf)
    # stream = BytesIO(buf)
    loop = asyncio.get_event_loop()
    reader = asyncio.StreamReader()
    protocol = asyncio.StreamReaderProtocol(reader)
    await loop.connect_read_pipe(lambda: protocol, os.fdopen(r, 'r'))
    return reader


@contextmanager
def exception_guard(message_on_exit: str = 'exit'):
    try:
        yield None
    finally:
        print(message_on_exit)
        return True  # indicates that exception was gracefully handled


async def main():
    client_hello_bytes = bytes.fromhex("""
    0303933EA21EC3802A561550
    EC78D6ED51AC2439D7E749C31BC3A345
    6165889684CA000004FF88FF89010000
    13000D00060004EEEEEFEFFF01000100
    00 17 00 00
    """)
    reader = await reader_from_buffer(client_hello_bytes)
    client_hello = ClientHello()
    await client_hello.deserialize(reader)
    client_hello_expected = ClientHello()
    client_hello_expected.session_id = b""
    client_hello_expected.random = bytes.fromhex("933EA21EC3802A561550EC78D6ED51AC 2439D7E749C31BC3A3456165889684CA")
    client_hello_expected.cipher_suites = [0xFF88, 0xFF89]
    ext1 = Extension()
    ext1.type = ExtensionType.signature_algorithms
    ext1.supported_signature_algorithms = [SignatureAndHashAlgorithm(HashAlgorithm(0xEE), SignatureAlgorithm(0xEE)),
                                           SignatureAndHashAlgorithm(HashAlgorithm(0xEF), SignatureAlgorithm(0xEF))]
    ext2 = Extension()
    ext2.type = ExtensionType.renegotiation_info
    ext2.renegotiated_connection = b""
    ext3 = Extension()
    ext3.type = ExtensionType.extended_master_secret
    client_hello_expected.extensions = [ext1, ext2, ext3]
    assert client_hello == client_hello_expected


if __name__ == '__main__':
    asyncio.run(main())
