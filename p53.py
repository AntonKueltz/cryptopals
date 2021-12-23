from binascii import hexlify
from os import urandom
from typing import Dict, List, Tuple

from main import Solution
from p09 import pkcs7
from p52 import mdhash

from Crypto.Cipher import AES


def _generate_messages(k: int) -> Tuple[List[Tuple[bytes, bytes]], bytes]:
    h = b'\x00\x00'
    state_size = len(h)
    collisions = []
    hashed = b''

    while k > 0:
        lookup = {}
        prefix = b'\x00' * AES.block_size * (2 ** (k - 1))
        pre_hash = mdhash(prefix, h, nopadding=True)

        for _ in range(2 ** (state_size * 8)):
            m = urandom(state_size)
            lookup[mdhash(m, h)] = m

        m = urandom(state_size)
        hashed = mdhash(m, pre_hash)
        while hashed not in lookup:
            m = urandom(state_size)
            hashed = mdhash(m, pre_hash)

        single_block_hash = mdhash(lookup[hashed], h)
        klen_block_hash = mdhash(prefix + m, h)
        assert single_block_hash == klen_block_hash
        assert klen_block_hash == hashed
        assert hashed == single_block_hash

        collisions.append((prefix + m, lookup[hashed]))

        k -= 1
        h = hashed

    return collisions, hashed


def _block_hash_map(M: bytes) -> Dict[bytes, int]:
    state_to_index = {}
    h = b'\x00\x00'
    M = pkcs7(M)

    for i in range(len(M) // AES.block_size):
        state_to_index[h] = i

        start = i * AES.block_size
        end = start + AES.block_size
        block = M[start:end]

        hashed = mdhash(block, h, nopadding=True)
        h = hashed

    return state_to_index


def _generate_prefix(length: int, pairs: List[Tuple[bytes, bytes]]) -> bytes:
    length *= AES.block_size
    prefix = b''

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

    bridge_index = intermediate_hashes[final_state]
    bridge_offset = bridge_index * AES.block_size
    print(f'Bridge block is at index {bridge_index}')

    prefix = _generate_prefix(bridge_index, collision_pairs)
    assert mdhash(prefix, b'\x00\x00', nopadding=True) == final_state
    assert len(prefix) == (bridge_index * AES.block_size)

    preimage = prefix + M[bridge_offset:]
    hashed = mdhash(M, b'\x00\x00')
    assert len(preimage) == len(M)
    assert mdhash(preimage, b'\x00\x00') == hashed

    return f'Found a preimage for message M with length 2^{k}\n' \
           f'M = {hexlify(M).decode()[:32]}...\n' \
           f'hash = {hexlify(hashed).decode()}\n' \
           f'preimage = {hexlify(preimage).decode()[:32]}...'


def main() -> Solution:
    return Solution('53: Kelsey and Schneier\'s Expandable Messages', p53)
