import asyncio
import os

pass_payload = True
message_len = 100 * 1024 * 1024


async def tcp_echo_client(message: str | bytes):
    reader, writer = await asyncio.open_connection('localhost', 8888)

    if pass_payload:
        print(f"Send payload of length {len(message)} bytes")
        writer.write(message)
        read_len = len(message)
    else:
        print(f'Send: {message!r}')
        data = message.encode()
        read_len = len(data)
        writer.write(message.encode())
    # await writer.drain()

    data = await reader.readexactly(read_len)
    if pass_payload:
        print(f"Received payload of {len(data)} bytes")
        assert data == message
    else:
        print(f'Received: {data.decode()!r}')

    print('Close the connection')
    writer.close()
    await writer.wait_closed()


async def main():
    if pass_payload:
        await tcp_echo_client(os.urandom(message_len))
    else:
        await tcp_echo_client('Hello World!')


if __name__ == '__main__':
    asyncio.run(main())
