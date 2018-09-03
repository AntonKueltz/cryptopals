from binascii import hexlify
from os import urandom

from p09 import pkcs7
from p52 import mdhash


def _find_collision(h1, h2):
    lookup = {}

    for _ in xrange(2**8):
        m = urandom(2)
        hashed = mdhash(m, h1)
        lookup[hashed] = m

    m = urandom(2)
    hashed = mdhash(m, h2)
    while hashed not in lookup:
        m = urandom(2)
        hashed = mdhash(m, h2)

    return lookup[hashed], m, hashed


def _generate_states(k):
    funnel = []
    initial_states = set()

    while len(initial_states) != 2 ** k:
        initial_states.add(urandom(2))
    states = list(initial_states)

    while len(states) != 1:
        next_states = []

        for i in range(0, len(states), 2):
            h1, h2 = states[i], states[i+1]
            m1, m2, h = _find_collision(h1, h2)

            funnel.append((h1, m1))
            funnel.append((h2, m2))
            next_states.append(h)

        states = next_states[:]
        if len(next_states) == 1:
            funnel.append((h, None))

    return funnel[::-1]


def _generate_suffix(m, funnel):
    target_states = {h: i for (i, (h, _)) in enumerate(funnel) if i > len(funnel) / 2}

    glue = urandom(2)
    hashed = mdhash(m + glue, '\x00\x00')
    while hashed not in target_states:
        glue = urandom(2)
        hashed = mdhash(m + glue, '\x00\x00')

    m = pkcs7(m + glue)
    i = target_states[hashed]
    while i != 0:
        h, a = funnel[i]
        m += pkcs7(a)
        i = (i - 1) / 2

    return m


def p54():
    funnel = _generate_states(8)
    assert funnel[0][1] is None
    prediction = mdhash('', funnel[0][0])
    print 'Prediction hash = {}'.format(hexlify(prediction))

    m = 'This message predicts every result for the coming baseball season'
    m = _generate_suffix(m, funnel)

    hashed = mdhash(m, '\x00\x00')
    assert hashed == prediction
    return 'Generated message {} with hash = {}'.format(repr(m), hexlify(hashed))


def main():
    from main import Solution
    return Solution('54: Kelsey and Kohno\'s Nostradamus Attack', p54)
