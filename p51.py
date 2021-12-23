from os import urandom
from zlib import compress

from main import Solution
from p11 import aes_cbc_encrypt


def _detect_compressed_size(ptxt: bytes) -> int:
    key, iv = urandom(16), urandom(16)
    request = f'POST / HTTP/1.1\n' \
              f'Host: hapless.com\n' \
              f'Cookie: sessionid=TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE=\n' \
              f'Content-Length: {len(ptxt)}\n'
    request = request.encode() + ptxt

    ctxt = aes_cbc_encrypt(compress(request), key, iv)
    return len(ctxt)


def _calc_padding(content: bytes) -> bytes:
    padding = b'ABCDEFGHIJKLMNOP'
    curlen = _detect_compressed_size(content)
    i = 0

    while _detect_compressed_size(content + padding[:i]) == curlen:
        i += 1

    return padding[:i-1]


def p51() -> str:
    content = b'sessionid='
    shortest = [b'']

    while True:
        minlen = 1000000
        round_shortest = []
        padding = _calc_padding(content + shortest[0])

        for guess in range(0xff + 1):
            guess = int.to_bytes(guess, 1, byteorder='big')

            for cand in shortest:
                intxt = padding + content + cand + guess
                length = _detect_compressed_size(intxt)

                if length == minlen:
                    round_shortest.append(cand + guess)
                elif length < minlen:
                    round_shortest = [cand + guess]
                    minlen = length

        shortest = round_shortest[:]

        if len(shortest) == 1 and shortest[0][-1] == ord('\n'):
            return f'Session id = {shortest[0][:-1].decode()}'


def main() -> Solution:
    return Solution('51: Compression Ratio Side-Channel Attacks', p51)
