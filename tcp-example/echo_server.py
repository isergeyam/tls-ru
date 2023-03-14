import asyncio
from contextlib import contextmanager

pass_payload = False
message_len = 100 * 1024


class ExceptionGuard:
    def __init__(self, message_on_exit='exit'):
        self.message_on_exit = message_on_exit
        pass

    def __enter__(self):
        pass

    def __exit__(self, exc_type, exc_val, exc_tb):
        print(self.message_on_exit)
        return True  # indicates that exception was gracefully handled


@contextmanager
def exception_guard(message_on_exit: str = 'exit'):
    try:
        yield None
    finally:
        print(message_on_exit)
        return True  # indicates that exception was gracefully handled


async def handle_echo(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    peer = writer.get_extra_info('peername')
    with ExceptionGuard(f'exit client handler for peer {peer}'):
        while True:
            data = await reader.read(message_len)
            if not data:
                # Empty message means EOF
                assert reader.at_eof()
                return
            if pass_payload:
                print(f"Received payload of length {len(data)} bytes from {peer!r}")
                print("Sending the payload back")
            else:
                message = data.decode()
                print(f"Received {message!r} from {peer!r}")
                print(f"Send: {message!r}")
            writer.write(data)
            await writer.drain()

    # print("Close the connection")
    # writer.close()
    # await writer.wait_closed()


async def main():
    server = await asyncio.start_server(handle_echo, 'localhost', 8888)

    addrs = ', '.join(str(sock.getsockname()) for sock in server.sockets)
    print(f'Serving on {addrs}')

    async with server:
        await server.serve_forever()


if __name__ == '__main__':
    with exception_guard('shutdown server'):
        asyncio.run(main())
