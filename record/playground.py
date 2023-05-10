import io
from math import ceil, floor
import asyncio
import os
from contextlib import contextmanager
import sys
import typing as tp

from TLSTree import *
from cipher import *
from Kuznechik import Kuznechik

from record import RecordAlternative

from tools import HandshakeParser

import binascii

from record import Record
import asyncio
from contextlib import contextmanager
import os

from tools import HandshakeParser
from tools.handshaketypes import *

from tools.utils import *


@contextmanager
def exception_guard(message_on_exit: str = 'exit'):
    try:
        yield None
    finally:
        print(message_on_exit)
        return True  # indicates that exception was gracefully handled


async def handle_read_records(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    global server
    rec = RecordAlternative(reader, writer)

    parser = HandshakeParser()

    hr, hw = rec.handshaker()

    res = await parser(hr)
    print(res)

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
    reader, writer = await asyncio.open_connection('localhost', 8888)
    rec = RecordAlternative(reader, writer)
    hr, hw = rec.handshaker()

    rc = generate_random()

    print("random client generated\n", binascii.hexlify(rc))

    clienthello = ClientHello(rc)

    hw.write(clienthello.to_bytes())

    print(binascii.hexlify(clienthello.to_bytes()))




    print("client has writen")

    await server


if __name__ == '__main__':
    with exception_guard('shutdown server'):
        asyncio.run(main())
