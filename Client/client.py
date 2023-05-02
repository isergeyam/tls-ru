import binascii

from record import Record
import asyncio
from contextlib import contextmanager
import os

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


message_len = 100 * 1024


async def client():
    print("clinet")
    reader, writer = await asyncio.open_connection('localhost', 8888)
    parser = HandshakeParser()
    rec = Record()

    rc = generate_random()

    print("random client generated\n", binascii.hexlify(rc))

    clienthello = ClientHello(rc)

    if debug:
        print(clienthello)

    rec.create_records(22, clienthello.to_bytes())

    rec.send_records(writer)

    my_type, mybuffer = await rec.get_reader(reader)

    res = parser(mybuffer)

    rs = res["random"].value

    print("-----\nserver random\n", binascii.hexlify(rs), "\n---------")

    if debug:
        print(res)

    my_type, mybuffer2 = await rec.get_reader(reader)

    res = parser(mybuffer2)

    if debug:
        print(res)



    print(get_name_from_cert(res))

    x, y = get_point_from_cert(res)
    print(binascii.hexlify(x))
    print(binascii.hexlify(y))

    curve = get_curve_from_cert(res)
    print(binascii.hexlify(curve))
    print(res["body"][0]["certificate"][0][6][0][1][0])

    writer.close()


async def main():
    await client()


if __name__ == '__main__':
    asyncio.run(main())
