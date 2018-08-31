from base64 import b64decode
from operator import itemgetter
from os import urandom

from Crypto.Cipher import ARC4


def _rc4_encryption_oracle(request):
    cookie = b64decode('QkUgU1VSRSBUTyBEUklOSyBZT1VSIE9WQUxUSU5F')
    fresh_key = urandom(16)

    cipher = ARC4.new(fresh_key)
    return cipher.encrypt(request + cookie)


def p56():
    cookie_len = len(_rc4_encryption_oracle(''))
    z16, z32 = 15, 31
    z16_bias, z32_bias = 0xf0, 0xe0
    plaintext = ['?'] * cookie_len

    for i in range((cookie_len / 2) + 1):
        offset = z16 - i
        request = 'A' * offset
        z16_map, z32_map = {}, {}
        check_z32 = z32 < (len(request) + cookie_len)

        for j in xrange(2**24):
            result = _rc4_encryption_oracle(request)

            try:
                z16_map[result[z16]] += 1
            except KeyError:
                z16_map[result[z16]] = 1

            if check_z32:
                try:
                    z32_map[result[z32]] += 1
                except KeyError:
                    z32_map[result[z32]] = 1

        z16_char = max(z16_map.items(), key=itemgetter(1))[0]
        plaintext[z16 - offset] = chr(ord(z16_char) ^ z16_bias)

        if check_z32:
            z32_char = max(z32_map.items(), key=itemgetter(1))[0]
            plaintext[z32 - offset] = chr(ord(z32_char) ^ z32_bias)

    return ''.join(plaintext)


def main():
    from main import Solution
    return Solution('56: RC4 Single-Byte Biases', p56)
