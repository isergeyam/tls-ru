from result import Result, fbyteresult


def TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC():
    return fbyteresult("ff89")


def TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC():
    return fbyteresult("ff88")


def Sesion_id(value=bytearray()):
    return Result("bytes", value, len(value), 1)


def CipherSuites(values):
    return Result("array", values, 2 * len(values), 2)


def CompressionMethods(values=bytearray(1)):
    return Result("array", values, len(values), 1)


def Version(major="03", minor="03"):
    return Result("fdict", {"major": fbyteresult(major), "minor": fbyteresult(minor)}, 2, 0)


def extended_master_secret():
    return Result("variant", Result("bytes", bytearray(), 0, 2), 0, 2, 23)

def 


a = []

a.append(TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC())

a[0].value = bytearray()

print(a)
print(extended_master_secret())
