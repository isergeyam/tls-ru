from cipher.P_50_1_113_2016.hmacGOST import HMAC


# PRF_TLS_GOSTR3411_2012_256
# PRF_TLS_GOSTR3411_2012_512

class PRF:
    def __init__(self, key: bytearray, mode: int):
        self.hmac = HMAC(key, mode)
        self.mode = mode

    def __call__(self, key: bytearray):
        self.hmac = self.hmac(key)
        return self

    def digest(self, label: bytearray, seed: bytearray, size: int):
        A = [label + seed]
        n = size // self.mode

        for i in range(1, n + 1):
            A.append(self.hmac.digest(A[i - 1]))

        P = []
        for i in range(1, n + 1):
            P.append(self.hmac.digest(A[i] + label + seed))

        res = b''
        for i in P:
            res += i
        return bytearray(res)
