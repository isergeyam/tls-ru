import asyncio
import binascii

from contextlib import contextmanager
import sys

from record import Record

from tools import HandshakeParser
from tools.handshaketypes import *

debug = False


@contextmanager
def exception_guard(message_on_exit: str = 'exit'):
    try:
        yield None
    finally:
        print(message_on_exit)
        return True  # indicates that exception was gracefully handled


async def handle_handshake(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, buffer, record):
    parser = HandshakeParser()
    rec = Record()
    rec2 = Record()
    res = parser(buffer)

    if debug:
        print(res)

    rc = res["random"].value

    print("-----\nclient random\n", binascii.hexlify(rc), "\n---------")

    await asyncio.sleep(1)

    rs = generate_random()

    print("random server generated\n", binascii.hexlify(rs))

    serverhello = ServerHello(rs)

    if debug:
        serverhello

    rec.create_records(22, serverhello.to_bytes())

    rec.send_records(writer)

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

    if debug:
        print(cert)
    rec2.create_records(22, cert.to_bytes())

    rec2.send_records(writer)

    sys.stdout.flush()


async def handle_read_records(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    cnt = 0

    rec = Record()

    my_type, mybuffer = await rec.get_reader(reader)

    if my_type == 22:
        await handle_handshake(reader, writer, mybuffer, rec)

    sys.stdout.flush()


async def start_server():
    server = await asyncio.start_server(handle_read_records, 'localhost', 8888)

    addrs = ', '.join(str(sock.getsockname()) for sock in server.sockets)
    print(f'Serving on {addrs}')

    async with server:
        await server.serve_forever()


async def main():
    await start_server()


if __name__ == '__main__':
    with exception_guard('shutdown server'):
        asyncio.run(main())
