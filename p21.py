from main import Solution


class MersenneTwister():
    def __init__(self, seed: int):
        self.idx = 0
        self.MT = [i for i in range(624)]
        self.MT[0] = seed

        for i in range(1, 624):
            self.MT[i] = 0xffffffff & (1812433253 * (self.MT[i-1] ^ (self.MT[i-1] >> 30)) + i)

    def _generate(self):
        for i in range(624):
            y = (self.MT[i] & 0x80000000) + (self.MT[(i+1) % 624] &
                                             0x7fffffff)
            self.MT[i] = self.MT[(i+397) % 624] ^ (y >> 1)

            if y % 2:
                self.MT[i] = self.MT[i] ^ 2567483615

    def extract(self) -> int:
        if self.idx == 0:
            self._generate()

        y = self.MT[self.idx]
        y = y ^ (y >> 11)
        y = y ^ ((y << 7) & 2636928640)
        y = y ^ ((y << 15) & 4022730752)
        y = y ^ (y >> 18)

        self.idx = (self.idx + 1) % 624
        return y & 0xffffffff


def p21() -> str:
    mt = MersenneTwister(0)
    out = [str(mt.extract()) for _ in range(5)]

    return f'PRNG output - {", ".join(out)}'


def main() -> Solution:
    return Solution('21: Implement the MT19937 Mersenne Twister RNG', p21)
