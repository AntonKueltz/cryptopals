from binascii import unhexlify
from operator import itemgetter


def char_freq(chars):
    freq = 0
    most_freq_letters = 'etaoinhs'

    for c in chars:
        if c in most_freq_letters:
            freq += 1

    return freq


def get_single_byte_key(ctxt):
    key_to_char_count = {}

    for key in range(0xff + 1):
        chars = []
        for c in ctxt:
            chars.append(chr(ord(c) ^ key))
        key_to_char_count[key] = char_freq(chars)

    return max(key_to_char_count.items(), key=itemgetter(1))[0]


def single_byte_cipher(ctxt):
    key = chr(get_single_byte_key(ctxt))
    return ''.join(map(lambda c: chr(ord(key) ^ ord(c)), ctxt))


def p03():
    ctxt = unhexlify('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736')
    return single_byte_cipher(ctxt)


def main():
    from main import Solution
    return Solution('3: Single-byte XOR cipher', p03)
