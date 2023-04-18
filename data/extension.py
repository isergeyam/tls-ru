import asyncio
from enum import Enum
from dataclasses import dataclass
from async_io import StreamReader


class ExtensionType(Enum):
    signature_algorithms = 13
    extended_master_secret = 23
    renegotiation_info = 65281


class HashAlgorithm(Enum):
    gostr34112012_256 = 238
    gostr34112012_512 = 239


class SignatureAlgorithm(Enum):
    gostr34102012_256 = 238
    gostr34102012_512 = 239


@dataclass
class SignatureAndHashAlgorithm:
    hash: HashAlgorithm
    signature: SignatureAlgorithm


class Extension(object):
    async def _read_signature_algorithms(self, reader: StreamReader):
        length = await reader.read_int(2)
        assert length - 2 == await reader.read_int(2)
        length -= 2
        count = length // 2
        self.supported_signature_algorithms = []
        for _ in range(count):
            self.supported_signature_algorithms.append(
                SignatureAndHashAlgorithm(HashAlgorithm(await reader.read_int(1)),
                                          SignatureAlgorithm(await reader.read_int(1))))

    def __init__(self):
        pass

    async def deserialize(self, _reader: asyncio.StreamReader) -> int:
        reader = StreamReader(_reader)
        self.type = ExtensionType(await reader.read_int(2))
        match self.type:
            case ExtensionType.signature_algorithms:
                await self._read_signature_algorithms(reader)
            case ExtensionType.extended_master_secret:
                length = await reader.read_int(2)
                assert length == 0
            case ExtensionType.renegotiation_info:
                length = await reader.read_int(2)
                assert length - 1 == await reader.read_int(1)
                length -= 1
                self.renegotiated_connection = await reader.readexactly(length)
        return reader.count

    def __eq__(self, other):
        if not isinstance(other, Extension):
            return False
        if self.type != other.type:
            return False
        match self.type:
            case ExtensionType.signature_algorithms:
                return self.supported_signature_algorithms == other.supported_signature_algorithms
            case ExtensionType.renegotiation_info:
                return self.renegotiated_connection == other.renegotiated_connection
            case ExtensionType.extended_master_secret:
                return True
