from base64 import b64decode

from main import Solution
from p03 import char_freq, get_single_byte_key
from p05 import repeating_key_xor


def hamming(s1: bytes, s2: bytes) -> int:
    dist = 0

    for c1, c2 in zip(s1, s2):
        diff = c1 ^ c2
        dist += sum([1 for b in bin(diff) if b == '1'])

    return dist


def _best_key_lengths(data: bytes) -> map:
    dist_and_ksize = []

    for ksize in range(2, 41):
        b1, b2, b3, b4 = data[:ksize], data[ksize:2 * ksize], \
            data[2 * ksize: 3 * ksize], data[3 * ksize:4 * ksize]
        dists, blocks = [], [b1, b2, b3, b4]

        for i in range(len(blocks) - 2):
            for j in range(i + 1, len(blocks) - 1):
                dists.append(hamming(blocks[i], blocks[j]) / ksize)

        dist_and_ksize.append((sum(dists) / len(dists), ksize))

    return map(lambda pair: pair[1], sorted(dist_and_ksize)[:3])


def break_repeating_key(data: bytes) -> bytes:
    keylens = _best_key_lengths(data)
    best_freq, ptxt = 0, b''

    for keylen in keylens:
        key = []
        blocks = [[] for _ in range(keylen)]

        for i, c in enumerate(data):
            blocks[i % keylen].append(c)
        blocks = map(bytes, blocks)

        for block in blocks:
            key.append(get_single_byte_key(block))
        key = bytes(key)

        txt = repeating_key_xor(data, key)
        cur_freq = char_freq(txt)

        if cur_freq > best_freq:
            best_freq = cur_freq
            ptxt = txt

    return ptxt


def p06() -> bytes:
    with open('Data/6.txt', 'rb') as f:
        data = b64decode(f.read().replace(b'\n', b''))
        return break_repeating_key(data)


def main() -> Solution:
    return Solution('6: Break repeating-key XOR', p06)
