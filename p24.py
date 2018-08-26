from os import urandom
from random import randint

from p21 import MersenneTwister


def _mt_stream_cipher(txt, seed):
    out = ''
    seed = seed & 0xffff
    mt = MersenneTwister(seed)
    keystream = mt.extract()

    for c in txt:
        keystream = mt.extract()
        mask = keystream & 0xff
        out += chr(ord(c) ^ mask)

    return out


def p24():
    known = 'A' * 14
    prefix = urandom(randint(1, 10))
    seed = randint(0, 0xffff)
    print 'Seeded MT cipher with value {}'.format(seed)
    ctxt = _mt_stream_cipher(prefix + known, seed)

    for guess_seed in range(0, 0xffff + 1):
        ptxt = _mt_stream_cipher(ctxt, guess_seed)
        if known in ptxt:
            break

    return 'Recovered seed {}'.format(guess_seed)


def main():
    from main import Solution
    return Solution('24: Create the MT19937 stream cipher and break it', p24)
