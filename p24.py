from os import urandom
from random import randint

from main import Solution
from p21 import MersenneTwister


def _mt_stream_cipher(txt: bytes, seed: int) -> bytes:
    out = []
    seed = seed & 0xffff
    mt = MersenneTwister(seed)

    for c in txt:
        keystream = mt.extract()
        mask = keystream & 0xff
        out.append(c ^ mask)

    return bytes(out)


def p24() -> str:
    known = b'A' * 14
    prefix = urandom(randint(1, 10))
    seed = randint(0, 0xffff)
    print(f'Seeded MT cipher with value {seed}')
    ctxt = _mt_stream_cipher(prefix + known, seed)

    for guess_seed in range(0, 0xffff + 1):
        ptxt = _mt_stream_cipher(ctxt, guess_seed)
        if known in ptxt:
            break

    return f'Recovered seed {guess_seed}'


def main() -> Solution:
    return Solution('24: Create the MT19937 stream cipher and break it', p24)
