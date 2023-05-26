import asyncio

from contextlib import contextmanager

from record.client import HandShakerClient

from record.server import HandShakerServer

import time
import threading


def stop_script():
    duration = 10
    time.sleep(duration)

    print("Time's up! Script is stopping.")

    import os
    import signal
    os.kill(os.getpid(), signal.SIGINT)


@contextmanager
def exception_guard(message_on_exit: str = 'exit'):
    try:
        yield None
    finally:
        print(message_on_exit)
        return True  # indicates that exception was gracefully handled


async def connect():
    reader, writer = await asyncio.open_connection('www.cryptopro.ru', 4444)

    # reader, writer = await asyncio.open_connection('tlsgost-2001.cryptopro.ru', 4443)

    # reader, writer = await asyncio.open_connection('gosuslugi.ru', 443)

    handshakerclient = HandShakerClient(reader, writer)

    await handshakerclient.handshake()
    print("client done!")


async def main():
    task = asyncio.create_task(connect())
    duration = 5
    await asyncio.sleep(duration)

    # Cancel all running coroutines

    print("canceled")
    task.cancel()


if __name__ == '__main__':
    stop_thread = threading.Thread(target=stop_script)
    stop_thread.start()
    try:
        asyncio.run(main())
    except asyncio.CancelledError:
        pass
