'''
Implementation of the Secure Hashing Algorithm (SHA1)
Author: Anton Kueltz
'''


class SHA1():
    def __init__(self, m):
        self.BLOCKSIZE = 512 / 8
        self.MAX_MSG_LEN = 2**64 - 1
        self.msg = m
        self.h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
        self.hash = self.digest()

    def __str__(self):
        return hex(self.hash)[2:-1]

    @staticmethod
    def word(str32bit):
        w = 0
        degree = 0

        while str32bit != '':
            byt = str32bit[-1]
            w += ord(byt) * (0xFF+1)**degree
            degree += 1
            str32bit = str32bit[:-1]

        return w

    def pad(self):
        msglen = len(self.msg)
        msgbits = msglen * 8
        if msgbits > self.MAX_MSG_LEN:
            print 'Message exceeds limit of 2^64-1 bits'
            return

        padstring = chr(0x80)

        hexlen = ''
        while msgbits > 0:
            hexlen = chr(msgbits % (0xFF+1)) + hexlen
            msgbits /= (0xFF+1)

        while (msglen + len(padstring)) % self.BLOCKSIZE != 56:
            padstring += chr(0x00)

        padstring += (8-len(hexlen)) * chr(0x00) + hexlen
        self.msg += padstring

    def digest(self):
        self.pad()
        blocks = len(self.msg) / self.BLOCKSIZE

        for block in range(blocks):
            chunk = self.msg[block*self.BLOCKSIZE:(block+1)*self.BLOCKSIZE]

            w = map(SHA1.word, [chunk[i*4:(i+1)*4] for i in range(16)])
            for i in range(16, 80):
                neww = (w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16])
                neww = ((neww << 1) | ((neww >> 31) & 0x1)) & 0xFFFFFFFF
                w.append(neww)

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

                tmp = ((a << 5) | ((a >> 27) & 0x1F)) & 0xFFFFFFFF
                tmp += (f + e + k + w[i]) & 0xFFFFFFFF
                e = d
                d = c
                c = ((b << 30) | ((b >> 2) & 0x3FFFFFFF)) & 0xFFFFFFFF
                b = a
                a = tmp

            self.h[0] = (self.h[0] + a) & 0xFFFFFFFF
            self.h[1] = (self.h[1] + b) & 0xFFFFFFFF
            self.h[2] = (self.h[2] + c) & 0xFFFFFFFF
            self.h[3] = (self.h[3] + d) & 0xFFFFFFFF
            self.h[4] = (self.h[4] + e) & 0xFFFFFFFF

        return ((self.h[0] << 128) | (self.h[1] << 96) | (self.h[2] << 64) |
                (self.h[3] << 32) | self.h[4])
