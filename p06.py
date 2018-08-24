from base64 import b64decode

from p03 import char_freq, get_single_byte_key
from p05 import repeating_key_xor


def hamming(s1, s2):
    dist = 0

    for c1, c2 in zip(s1, s2):
        diff = ord(c1) ^ ord(c2)
        dist += sum([1 for b in bin(diff) if b == '1'])

    return dist


def _best_key_lengths(data):
    avg_dist = []

    for ksize in range(2, 41):
        b1, b2, b3, b4 = data[:ksize], data[ksize:2 * ksize], \
            data[2 * ksize: 3 * ksize], data[3 * ksize:4 * ksize]
        dists, blocks = [], [b1, b2, b3, b4]

        for i in range(len(blocks) - 2):
            for j in range(i + 1, len(blocks) - 1):
                dists.append(hamming(blocks[i], blocks[j]) / float(ksize))

        avg_dist.append((sum(dists) / len(dists), ksize))

    return sorted(avg_dist)[:3]


def break_repeating_key(data):
    keylens = _best_key_lengths(data)
    best_freq, ptxt = 0, ''

    for _, keylen in keylens:
        key = ''
        blocks = [''] * keylen
        for i, c in enumerate(data):
            blocks[i % keylen] += c

        for block in blocks:
            key += chr(get_single_byte_key(block))

        txt = repeating_key_xor(data, key)
        cur_freq = char_freq(txt)

        if cur_freq > best_freq:
            best_freq = cur_freq
            ptxt = txt

    return ptxt


def p06():
    with open('Data/6.txt') as f:
        data = b64decode(f.read().replace('\n', ''))
        return break_repeating_key(data)


def main():
    from main import Solution
    return Solution('6: Break repeating-key XOR', p06)
