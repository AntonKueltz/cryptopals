class MerkleDamgardHash(object):
    def __init__(self):
        self.BLOCKSIZE = 512 / 8

    def word(self, str32bit):
        w = 0
        degree = 0

        while str32bit != '':
            byt = str32bit[-1]
            w += ord(byt) * (0xFF+1)**degree
            degree += 1
            str32bit = str32bit[:-1]

        return w

    def rotateleft(self, int32bit, amt):
        mask = 0
        for i in range(amt):
            mask |= 2**i
        rotated = (int32bit << amt) | ((int32bit >> (32 - amt)) & mask)
        return rotated & 0xFFFFFFFF

    def pad(self, msg):
        msglen = len(msg)
        msgbits = (msglen * 8) % (2**64)

        padstring = chr(0x80)

        hexlen = ''
        while msgbits > 0:
            hexlen = chr(msgbits % (0xFF+1)) + hexlen
            msgbits /= (0xFF+1)

        while (msglen + len(padstring)) % self.BLOCKSIZE != (448 / 8):
            padstring += chr(0x00)

        padstring += (8-len(hexlen)) * chr(0x00) + hexlen
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
            print 'Message exceeds limit of 2^64-1 bits'
            return
        else:
            return super(SHA1, self).pad(msg)

    def hash(self, msg):
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
                    f = (d ^ (b & (c ^ d))) & 0xFFFFFFFF
                    k = 0x5A827999
                elif i in range(20, 40):
                    f = (b ^ c ^ d) & 0xFFFFFFFF
                    k = 0x6ED9EBA1
                elif i in range(40, 60):
                    f = ((b & c) | (b & d) | (c & d)) & 0xFFFFFFFF
                    k = 0x8F1BBCDC
                elif i in range(60, 80):
                    f = (b ^ c ^ d) & 0xFFFFFFFF
                    k = 0xCA62C1D6

                tmp = self.rotateleft(a, 5)
                tmp += (f + e + k + w[i]) & 0xFFFFFFFF
                e = d
                d = c
                c = self.rotateleft(b, 30)
                b = a
                a = tmp

            self.h = [(r+s) % 2**32 for r, s in zip(self.h, [a, b, c, d, e])]

        hashed = ((self.h[0] << 128) | (self.h[1] << 96) | (self.h[2] << 64) |
                  (self.h[3] << 32) | self.h[4])
        self.h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]

        return hex(hashed)[2:-1]


class MD4(MerkleDamgardHash):
    def __init__(self, backdoored=False, backdoor=None):
        super(MD4, self).__init__()
        self.h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]
        self.X = None
        self.backdoored = backdoored

        if self.backdoored:
            self.backdoor = backdoor
            self.h = map(self.low_bytes_to_high, self.backdoor)

    def pad(self, msg):
        padded = super(MD4, self).pad(msg)
        return padded[:-8] + padded[-8:][::-1]

    def low_bytes_to_high(self, int32):
        b0, b1, b2, b3 = [(int32 >> i * 8) & 0xFF for i in range(4)]
        return b0 << 24 | b1 << 16 | b2 << 8 | b3

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
        tmp = (tmp + 0x5A827999) & 0xFFFFFFFF
        self.h[a] = self.rotateleft(tmp, s)

    def round3(self, a, b, c, d, i, s):
        tmp = self.h[a] + MD4.h(self.h[b], self.h[c], self.h[d]) + self.X[i]
        tmp = (tmp + 0x6ED9EBA1) & 0xFFFFFFFF
        self.h[a] = self.rotateleft(tmp, s)

    def hash(self, msg):
        padded = self.pad(msg)
        blocks = len(padded) / self.BLOCKSIZE

        for i in range(blocks):
            chunk = padded[i*self.BLOCKSIZE:(i+1)*self.BLOCKSIZE]
            self.X = map(self.word, [chunk[j*4:(j+1)*4] for j in range(16)])
            self.X = map(self.low_bytes_to_high, self.X)

            if self.backdoored:
                self.h = map(self.low_bytes_to_high, self.backdoor)

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

            self.h[0] = (self.h[0] + AA) & 0xFFFFFFFF
            self.h[1] = (self.h[1] + BB) & 0xFFFFFFFF
            self.h[2] = (self.h[2] + CC) & 0xFFFFFFFF
            self.h[3] = (self.h[3] + DD) & 0xFFFFFFFF

        hashed = ((self.low_bytes_to_high(self.h[0]) << 96) |
                  (self.low_bytes_to_high(self.h[1]) << 64) |
                  (self.low_bytes_to_high(self.h[2]) << 32) |
                  self.low_bytes_to_high(self.h[3]))
        self.h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]

        return hex(hashed)[2:-1]
