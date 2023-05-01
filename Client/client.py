from record import Record
import asyncio
from contextlib import contextmanager
import os


@contextmanager
def exception_guard(message_on_exit: str = 'exit'):
    try:
        yield None
    finally:
        print(message_on_exit)
        return True  # indicates that exception was gracefully handled


message_len = 100 * 1024
my_message = os.urandom(message_len)


async def client():
    print("clinet")
    reader, writer = await asyncio.open_connection('localhost', 8888)
    for i in range(10):
        rec = Record()
        rec.create_records(0x23, my_message)

        rec.send_records(writer)
        response = await reader.readline()
        print(f"Response: {response.decode().strip()}")
    writer.close()


async def main():
    await client()


if __name__ == '__main__':
    with exception_guard('shutdown server'):
        asyncio.run(main())
