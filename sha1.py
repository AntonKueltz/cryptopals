class SHA1():
    def __init__(self, backdoored=False, backdoor=None):
        self.BLOCKSIZE = 512 / 8
        self.MAX_MSG_LEN = 2**64 - 1
        self.h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
        self.backdoored = backdoored

        if self.backdoored:
            self.backdoor = backdoor
            self.h = self.backdoor[:]

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

    @staticmethod
    def rotateleft(int32bit, amt):
        mask = 0
        for i in range(amt):
            mask |= 2**i
        rotated = (int32bit << amt) | ((int32bit >> (32 - amt)) & mask)
        return rotated & 0xFFFFFFFF

    def pad(self, msg):
        msglen = len(msg)
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
        return msg + padstring

    def hash(self, msg):
        padded = self.pad(msg)
        blocks = len(padded) / self.BLOCKSIZE

        for block in range(blocks):
            chunk = padded[block*self.BLOCKSIZE:(block+1)*self.BLOCKSIZE]

            w = map(SHA1.word, [chunk[i*4:(i+1)*4] for i in range(16)])
            for i in range(16, 80):
                neww = (w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16])
                neww = SHA1.rotateleft(neww, 1)
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

                tmp = SHA1.rotateleft(a, 5)
                tmp += (f + e + k + w[i]) & 0xFFFFFFFF
                e = d
                d = c
                c = SHA1.rotateleft(b, 30)
                b = a
                a = tmp

            self.h = [(r+s) % 2**32 for r, s in zip(self.h, [a, b, c, d, e])]

        hashed = ((self.h[0] << 128) | (self.h[1] << 96) | (self.h[2] << 64) |
                  (self.h[3] << 32) | self.h[4])
        self.h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]

        return hex(hashed)[2:-1]
