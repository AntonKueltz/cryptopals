class MersenneTwister():
    def __init__(self, seed):
        self.idx = 0
        self.MT = range(624)
        self.MT[0] = seed

        for i in range(1, 624):
            self.MT[i] = 0xFFFFFFFF & (1812433253 * (self.MT[i-1] ^
                (self.MT[i-1] >> 30)) + i)

    def extract(self):
        if self.idx == 0:
            self.generate()

        y = self.MT[self.idx]
        y = y ^ (y >> 11)
        y = y ^ ((y << 7) & 2636928640)
        y = y ^ ((y << 15) & 4022730752)
        y = y ^ (y >> 18)

        self.idx = (self.idx + 1) % 624
        return y & 0xFFFFFFFF

    def generate(self):
        for i in range(624):
            y = (self.MT[i] & 0x80000000) + (self.MT[(i+1) % 624] &
                0x7FFFFFFF)
            self.MT[i] = self.MT[(i+397) % 624] ^ (y >> 1)

            if y % 2:
                self.MT[i] = self.MT[i] ^ 2567483615


def mt_stream_cipher(txt, seed):
    out = ''
    seed = seed & 0xFFFF
    mt = MersenneTwister(seed)
    keystream = mt.extract()

    for c in txt:
        keystream = mt.extract()
        mask = keystream & 0xFF
        out += chr(ord(c) ^ mask)

    return out
