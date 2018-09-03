from binascii import hexlify

from p09 import pkcs7

from Crypto.Cipher import AES


def mdhash(m, h, nopadding=False):
    state_size = len(h)
    m = str(m)
    if not nopadding:
        m = pkcs7(m)

    for block in range(len(m) / AES.block_size):
        cipher = AES.new(pkcs7(h), AES.MODE_ECB)
        start = block * AES.block_size
        end = start + AES.block_size
        h = cipher.encrypt(m[start:end])[:state_size]

    return h


def _find_collision(m, h):
    lookup = {}

    hashed = mdhash(m, h)
    while hashed not in lookup:
        lookup[hashed] = m
        m += 1
        hashed = mdhash(m, h)

    return str(m), str(lookup[hashed]), hashed


def _generate_collisions(n, start):
    h = '\x00\x00'
    collisions = []

    for level in xrange(n):
        prev_collisions = collisions[:]
        s1, s2, hashed = _find_collision(start, h)

        if not collisions:
            collisions = [s1, s2]
        else:
            collisions = [pkcs7(p) + s1 for p in prev_collisions]
            collisions += [pkcs7(p) + s2 for p in prev_collisions]

        h = hashed

    return collisions


def p52():
    expensive_size = 4
    expensive_state = '\x00' * expensive_size
    start = 0

    while True:
        lookup = {}
        collisions = _generate_collisions(expensive_size * 4, start)
        print 'Generated {} collisions...'.format(len(collisions))

        for m in collisions:
            h = mdhash(m, expensive_state)

            if h in lookup:
                collision = lookup[h]
                assert mdhash(m, '\x00\x00') == mdhash(collision, '\x00\x00')
                return 'Found collision for values {} and {}, hash = {}'.format(
                    hexlify(m), hexlify(collision), hexlify(h))
            else:
                lookup[h] = m

        start += 100000

    return 'No collisions found'


def main():
    from main import Solution
    return Solution('52: Iterated Hash Function Multicollisions', p52)
