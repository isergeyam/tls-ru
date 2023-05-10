from tools.error import *


class abyte:
    def __init__(self, buffer):
        self.buffer = buffer
        self.pos = 0

    def tell(self):
        return self.buffer.tell()

    async def read(self, size):
        return self.buffer.read(size)
