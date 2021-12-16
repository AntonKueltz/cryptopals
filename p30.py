from binascii import hexlify
from hmac import compare_digest
from os import urandom

from p28 import MerkleDamgardHash


class MD4(MerkleDamgardHash):
    def __init__(self, backdoored=False, backdoor=None):
        super(MD4, self).__init__()
        self.h = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]
        self.X = None
        self.backdoored = backdoored

        if self.backdoored:
            self.backdoor = backdoor
            self.h = self.backdoor[:]

    def pad(self, msg: bytes) -> bytes:
        padded = super(MD4, self).pad(msg)
        return padded[:-8] + padded[-8:][::-1]

    @staticmethod
    def f(x, y, z):
        return (x & y) | (~x & z)

    @staticmethod
    def g(x, y, z):
        return (x & y) | (x & z) | (y & z)

    @staticmethod
    def h(x, y, z):
        return x ^ y ^ z

    def round1(self, a, b, c, d, i, s):
        tmp = self.h[a] + MD4.f(self.h[b], self.h[c], self.h[d]) + self.X[i]
        self.h[a] = self.rotateleft(tmp, s)

    def round2(self, a, b, c, d, i, s):
        tmp = self.h[a] + MD4.g(self.h[b], self.h[c], self.h[d]) + self.X[i]
        tmp = (tmp + 0o13240474631) & 0xffffffff
        self.h[a] = self.rotateleft(tmp, s)

    def round3(self, a, b, c, d, i, s):
        tmp = self.h[a] + MD4.h(self.h[b], self.h[c], self.h[d]) + self.X[i]
        tmp = (tmp + 0o15666365641) & 0xffffffff
        self.h[a] = self.rotateleft(tmp, s)

    def hash(self, msg: bytes) -> bytes:
        padded = self.pad(msg)
        blocks = len(padded) // self.BLOCKSIZE

        for i in range(blocks):
            chunk = padded[i*self.BLOCKSIZE:(i+1)*self.BLOCKSIZE]
            self.X = [x for x in map(
                lambda word: int.from_bytes(word, byteorder='big'),
                [chunk[j*4:(j+1)*4] for j in range(16)]
            )]

            if self.backdoored:
                self.h = self.backdoor[:]

            AA, BB, CC, DD = self.h

            self.round1(0, 1, 2, 3, 0, 3)
            self.round1(3, 0, 1, 2, 1, 7)
            self.round1(2, 3, 0, 1, 2, 11)
            self.round1(1, 2, 3, 0, 3, 19)

            self.round1(0, 1, 2, 3, 4, 3)
            self.round1(3, 0, 1, 2, 5, 7)
            self.round1(2, 3, 0, 1, 6, 11)
            self.round1(1, 2, 3, 0, 7, 19)

            self.round1(0, 1, 2, 3, 8, 3)
            self.round1(3, 0, 1, 2, 9, 7)
            self.round1(2, 3, 0, 1, 10, 11)
            self.round1(1, 2, 3, 0, 11, 19)

            self.round1(0, 1, 2, 3, 12, 3)
            self.round1(3, 0, 1, 2, 13, 7)
            self.round1(2, 3, 0, 1, 14, 11)
            self.round1(1, 2, 3, 0, 15, 19)

            self.round2(0, 1, 2, 3, 0, 3)
            self.round2(3, 0, 1, 2, 4, 5)
            self.round2(2, 3, 0, 1, 8, 9)
            self.round2(1, 2, 3, 0, 12, 13)

            self.round2(0, 1, 2, 3, 1, 3)
            self.round2(3, 0, 1, 2, 5, 5)
            self.round2(2, 3, 0, 1, 9, 9)
            self.round2(1, 2, 3, 0, 13, 13)

            self.round2(0, 1, 2, 3, 2, 3)
            self.round2(3, 0, 1, 2, 6, 5)
            self.round2(2, 3, 0, 1, 10, 9)
            self.round2(1, 2, 3, 0, 14, 13)

            self.round2(0, 1, 2, 3, 3, 3)
            self.round2(3, 0, 1, 2, 7, 5)
            self.round2(2, 3, 0, 1, 11, 9)
            self.round2(1, 2, 3, 0, 15, 13)

            self.round3(0, 1, 2, 3, 0, 3)
            self.round3(3, 0, 1, 2, 8, 9)
            self.round3(2, 3, 0, 1, 4, 11)
            self.round3(1, 2, 3, 0, 12, 15)

            self.round3(0, 1, 2, 3, 2, 3)
            self.round3(3, 0, 1, 2, 10, 9)
            self.round3(2, 3, 0, 1, 6, 11)
            self.round3(1, 2, 3, 0, 14, 15)

            self.round3(0, 1, 2, 3, 1, 3)
            self.round3(3, 0, 1, 2, 9, 9)
            self.round3(2, 3, 0, 1, 5, 11)
            self.round3(1, 2, 3, 0, 13, 15)

            self.round3(0, 1, 2, 3, 3, 3)
            self.round3(3, 0, 1, 2, 11, 9)
            self.round3(2, 3, 0, 1, 7, 11)
            self.round3(1, 2, 3, 0, 15, 15)

            self.h[0] = (self.h[0] + AA) & 0xffffffff
            self.h[1] = (self.h[1] + BB) & 0xffffffff
            self.h[2] = (self.h[2] + CC) & 0xffffffff
            self.h[3] = (self.h[3] + DD) & 0xffffffff

        hashed = ((self.h[3] << 96) |
                  (self.h[2] << 64) |
                  (self.h[1] << 32) |
                   self.h[0])
        self.h = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]

        return int.to_bytes(hashed, 16, byteorder='little')


def _md4mac(key: bytes, msg: bytes) -> bytes:
    md4 = MD4()
    mac = md4.hash(key + msg)
    return mac


def p30() -> str:
    msg = b'comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound' \
          b'%20of%20bacon'
    key = urandom(16)
    auth = _md4mac(key, msg)

    msglen = len(msg) + len(key)
    dummy = b'\x00' * msglen
    m = MD4()
    glue = m.pad(dummy)[msglen:]

    hs = []
    authval = int.from_bytes(auth, byteorder='little')
    while authval:
        hs.append(int(authval & 0xffffffff))
        authval = authval >> 32

    inject = b';admin=true'
    tampered = MD4(backdoored=True, backdoor=hs)
    forged = tampered.hash(dummy + glue + inject)

    if compare_digest(forged, _md4mac(key, msg + glue + inject)):
        return f'Message: {msg + glue + inject}\n' \
               f'MAC: {hexlify(forged).decode()}'
    else:
        return 'Message Forgery Failed'


def main():
    from main import Solution
    return Solution('30: Break an MD4 keyed MAC using length extension', p30)
