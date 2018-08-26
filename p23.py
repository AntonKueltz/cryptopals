from random import randint

from p21 import MersenneTwister


def _untemper(mt_out):
    y = mt_out

    tmp1 = y & 0xffffc000
    tmp2 = (((y << 18) ^ y) >> 18) & 0xffffffff
    y = tmp1 | tmp2

    tmp1 = y & 0x7fff
    tmp2 = ((y << 15) & 4022730752) ^ y
    y = tmp1 | tmp2

    tmp1 = y & 0x7F
    tmp2 = (((tmp1 << 7) & 2636928640) ^ y) & 0x3f80
    tmp3 = (((tmp2 << 7) & 2636928640) ^ y) & 0x1fc000
    tmp4 = (((tmp3 << 7) & 2636928640) ^ y) & 0xfe00000
    tmp5 = (((tmp4 << 7) & 2636928640) ^ y) & 0xf0000000
    y = tmp1 | tmp2 | tmp3 | tmp4 | tmp5

    tmp1 = y & 0xffe00000
    tmp2 = (((y << 11) ^ y) & 0xffe00000) >> 11
    tmp3 = ((tmp2 >> 11) ^ y) & 0x3ff
    y = tmp1 | tmp2 | tmp3

    return y


def p23():
    seed = randint(0x10000000, 0xffffffff)
    mt = MersenneTwister(seed)
    output = [mt.extract() for _ in range(624)]
    print 'MT output - {}...'.format(', '.join(map(str, output[:5])))

    untempered = map(_untemper, output)
    clone = MersenneTwister(0)
    clone.MT = untempered
    cloned_output = [clone.extract() for _ in range(624)]

    return 'Clone output - {}...'.format(', '.join(map(str, output[:5])))


def main():
    from main import Solution
    return Solution('23: Clone an MT19937 RNG from its output', p23)
