from binascii import unhexlify
from operator import itemgetter

from main import Solution


def char_freq(chars: bytes) -> int:
    freq = 0
    most_freq_letters = b'etaoinhs'

    for c in chars:
        if c in most_freq_letters:
            freq += 1

    return freq


def get_single_byte_key(ctxt: bytes) -> int:
    key_to_char_count = {}

    for key in range(0xff + 1):
        chars = bytes([(c ^ key) for c in ctxt])
        key_to_char_count[key] = char_freq(chars)

    return max(key_to_char_count.items(), key=itemgetter(1))[0]


def single_byte_cipher(ctxt: bytes) -> bytes:
    key = get_single_byte_key(ctxt)
    return bytes(map(lambda c: key ^ c, ctxt))


def p03() -> bytes:
    ctxt = unhexlify(b'1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736')
    return single_byte_cipher(ctxt)


def main() -> Solution:
    return Solution('3: Single-byte XOR cipher', p03)
