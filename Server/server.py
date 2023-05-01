import asyncio

from contextlib import contextmanager
import sys

from record import Record


@contextmanager
def exception_guard(message_on_exit: str = 'exit'):
    try:
        yield None
    finally:
        print(message_on_exit)
        return True  # indicates that exception was gracefully handled


async def handle_read_records(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    cnt = 0
    while not reader.at_eof():
        rec = Record()


        message = bytearray()
        async for fragment in rec.read_records(reader):
            message += fragment
        print(f"Received {len(message)} fragment", cnt)
        cnt += 1

        response = b"Message received\n"
        writer.write(response)
        await writer.drain()

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
