from os import urandom

from p09 import pkcs7
from p52 import mdhash

from Crypto.Cipher import AES


def _generate_messages(k):
    h = '\x00\x00'
    state_size = len(h)
    collisions = []

    while k > 0:
        lookup = {}
        prefix = '\x00' * AES.block_size * (2 ** (k - 1))
        pre_hash = mdhash(prefix, h)

        for _ in range(2 ** (state_size * 8)):
            m = urandom(state_size)
            lookup[mdhash(m, h)] = m

        m = urandom(state_size)
        hashed = mdhash(m, pre_hash)
        while hashed not in lookup:
            m = urandom(state_size)
            hashed = mdhash(m, pre_hash)

        collisions.append((prefix + m, lookup[hashed]))

        k -= 1
        h = hashed

    return collisions, hashed


def _block_hash_map(M):
    block_to_index = {}
    h = '\x00\x00'
    M = pkcs7(M)

    for i in range(len(M) / AES.block_size):
        start = i * AES.block_size
        end = start + AES.block_size
        block = M[start:end]

        hashed = mdhash(block, h, nopadding=True)
        block_to_index[hashed] = i
        h = hashed

    return block_to_index


def _generate_prefix(length, pairs):
    length *= AES.block_size
    prefix = ''

    for long, short in pairs:
        segment = long if length >= len(long) else short

        segment = pkcs7(segment)
        prefix += segment
        length -= len(segment)

        if length == 0:
            return prefix


def p53():
    k = 16
    M = urandom(AES.block_size * 2 ** k)
    intermediate_hashes = _block_hash_map(M)

    collision_pairs, final_state = _generate_messages(k)
    while final_state not in intermediate_hashes:
        collision_pairs, final_state = _generate_messages(k)

    bridge_index = intermediate_hashes[final_state] + 1
    bridge_offset = bridge_index * AES.block_size
    print 'Bridge block is at index {}'.format(bridge_index)

    prefix = _generate_prefix(bridge_index, collision_pairs)
    assert len(prefix) == (bridge_index * AES.block_size)

    preimage = prefix + M[bridge_offset:]
    assert len(preimage) == len(M)
    assert mdhash(preimage, '\x00\x00') == mdhash(M, '\x00\x00')
    return 'Found a preimage for message M with length 2^{}'.format(k)


def main():
    from main import Solution
    return Solution('53: Kelsey and Schneier\'s Expandable Messages', p53)
