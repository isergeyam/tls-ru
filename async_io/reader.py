import asyncio


class StreamReader(object):
    def __init__(self, reader: asyncio.StreamReader):
        self.reader = reader
        self.count = 0

    async def readexactly(self, n):
        result = await self.reader.readexactly(n)
        self.count += len(result)
        return result

    async def read(self, n):
        result = await self.reader.read(n)
        self.count += len(result)
        return result

    async def read_int(self, length):
        self.count += length
        return int.from_bytes(await self.reader.readexactly(length), 'big')
