from hmac import compare_digest
from os import urandom


class MerkleDamgardHash(object):
    def __init__(self):
        self.BLOCKSIZE = 512 / 8

    def word(self, str32bit):
        w = 0
        degree = 0

        while str32bit != '':
            byt = str32bit[-1]
            w += ord(byt) * (0xff+1)**degree
            degree += 1
            str32bit = str32bit[:-1]

        return w

    def rotateleft(self, int32bit, amt):
        mask = 0
        for i in range(amt):
            mask |= 2**i
        rotated = (int32bit << amt) | ((int32bit >> (32 - amt)) & mask)
        return rotated & 0xffffffff

    def pad(self, msg):
        msglen = len(msg)
        msgbits = (msglen * 8) % (2**64)

        padstring = chr(0x80)

        hexlen = ''
        while msgbits > 0:
            hexlen = chr(msgbits % (0xff + 1)) + hexlen
            msgbits /= (0xff + 1)

        while (msglen + len(padstring)) % self.BLOCKSIZE != (448 / 8):
            padstring += '\x00'

        padstring += (8 - len(hexlen)) * '\x00' + hexlen
        return msg + padstring


class SHA1(MerkleDamgardHash):
    def __init__(self, backdoored=False, backdoor=None):
        super(SHA1, self).__init__()
        self.MAX_MSG_LEN = 2**64 - 1
        self.h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
        self.backdoored = backdoored

        if self.backdoored:
            self.backdoor = backdoor
            self.h = self.backdoor[:]

    def pad(self, msg):
        msglen = len(msg)
        msgbits = msglen * 8
        if msgbits > self.MAX_MSG_LEN:
            raise ValueError('Message exceeds limit of 2^64-1 bits')
        else:
            return super(SHA1, self).pad(msg)

    def hash(self, msg):
        msg = str(msg)
        padded = self.pad(msg)
        blocks = len(padded) / self.BLOCKSIZE

        for block in range(blocks):
            chunk = padded[block*self.BLOCKSIZE:(block+1)*self.BLOCKSIZE]

            w = map(self.word, [chunk[i*4:(i+1)*4] for i in range(16)])
            for i in range(16, 80):
                neww = (w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16])
                neww = self.rotateleft(neww, 1)
                w.append(neww)

            if self.backdoored:
                self.h = self.backdoor[:]

            [a, b, c, d, e] = self.h

            for i in range(80):
                if i in range(0, 20):
                    f = (d ^ (b & (c ^ d))) & 0xffffffff
                    k = 0x5a827999
                elif i in range(20, 40):
                    f = (b ^ c ^ d) & 0xffffffff
                    k = 0x6ed9eba1
                elif i in range(40, 60):
                    f = ((b & c) | (b & d) | (c & d)) & 0xffffffff
                    k = 0x8f1bbcdc
                elif i in range(60, 80):
                    f = (b ^ c ^ d) & 0xffffffff
                    k = 0xca62C1d6

                tmp = self.rotateleft(a, 5)
                tmp += (f + e + k + w[i]) & 0xffffffff
                e = d
                d = c
                c = self.rotateleft(b, 30)
                b = a
                a = tmp

            self.h = [(r+s) % 2**32 for r, s in zip(self.h, [a, b, c, d, e])]

        hashed = ((self.h[0] << 128) | (self.h[1] << 96) | (self.h[2] << 64) |
                  (self.h[3] << 32) | self.h[4])
        self.h = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xC3d2e1f0]

        return hex(hashed)[2:-1]


def sha1mac(key, msg):
    sha = SHA1()
    mac = sha.hash(key + msg)
    return mac


def p28():
    msg = 'Some super secret thing I dont want to share'
    key = urandom(16)
    auth = sha1mac(key, msg)

    assert compare_digest(auth, sha1mac(key, msg)) is True
    print 'Correct MAC accepted'

    badauth = sha1mac(urandom(16), msg)
    assert compare_digest(badauth, sha1mac(key, msg)) is False
    print 'Tampered MAC rejected'

    badmsg = 'I didnt write this'
    assert compare_digest(badauth, sha1mac(key, badmsg)) is False
    print 'Tampered message rejected'

    return 'All Tests Passed!'


def main():
    from main import Solution
    return Solution('28: Implement a SHA-1 keyed MAC', p28)
