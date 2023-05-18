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


async def main():
    reader, writer = await asyncio.open_connection('www.cryptopro.ru', 4444)

    # reader, writer = await asyncio.open_connection('tlsgost-2001.cryptopro.ru', 4443)

    # reader, writer = await asyncio.open_connection('gosuslugi.ru', 443)


    handshakerclient = HandShakerClient(reader, writer)

    await handshakerclient.handshake()

    print("client done!")


if __name__ == '__main__':
    asyncio.run(main())
