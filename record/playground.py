from record.record_protocol import RecordAlternative

import asyncio

from contextlib import contextmanager


from record.client import HandShakerClient

from record.server import HandShakerServer


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

    handshaker = HandShakerServer(rec)

    await handshaker.handshake()

    print("server done!")

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

    handshakerclient = HandShakerClient(rec)

    await handshakerclient.handshake()

    print("client done!")

    await server


if __name__ == '__main__':
    with exception_guard('shutdown server'):
        asyncio.run(main())
