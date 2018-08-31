from os import urandom
from zlib import compress

from p11 import aes_cbc_encrypt


def _detect_compressed_size(ptxt):
    key, iv = urandom(16), urandom(16)
    request = 'POST / HTTP/1.1\n' \
              'Host: hapless.com\n' \
              'Cookie: sessionid=TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE=\n' \
              'Content-Length: {}\n{}'.format(len(ptxt), ptxt)

    ctxt = aes_cbc_encrypt(compress(request), key, iv)
    return len(ctxt)


def _calc_padding(content):
    padding = 'ABCDEFGHIJKLMNOP'
    curlen = _detect_compressed_size(content)
    i = 0

    while _detect_compressed_size(content + padding[:i]) == curlen:
        i += 1

    return padding[:i-1]


def p51():
    content = 'sessionid='
    shortest = ['']

    while True:
        minlen = 1000000
        round_shortest = []
        padding = _calc_padding(content + shortest[0])

        for guess in map(chr, range(0xff + 1)):
            for cand in shortest:
                intxt = padding + content + cand + guess
                length = _detect_compressed_size(intxt)

                if length == minlen:
                    round_shortest.append(cand + guess)
                elif length < minlen:
                    round_shortest = [cand + guess]
                    minlen = length

        shortest = round_shortest[:]

        if len(shortest) == 1 and shortest[0][-1] == '\n':
            return 'Session id = {}'.format(shortest[0][:-1])


def main():
    from main import Solution
    return Solution('51: Compression Ratio Side-Channel Attacks', p51)
