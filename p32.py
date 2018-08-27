from binascii import unhexlify
from os import urandom
from time import time

from p31 import hmac_sha1, start_server, validate_sig

from requests import post, ConnectionError

master_key = urandom(16)


def p32():
    def _int_to_hexstr(i):
        s = hex(i).replace('0x', '').replace('L', '')
        return ('0' if len(s) & 1 else '') + s

    file = 'secrets.docx'
    expected = hmac_sha1(master_key, file)
    print 'Calculated HMAC-SHA1 - {}'.format(expected)

    rounds = 10
    known = ''
    while len(known) < len(expected):
        print known
        unknown = (len(expected) - len(known) - 2) * '0'
        longest, best = 0.0, ''

        for byt in range(0xff + 1):
            total = 0.0

            for _ in range(rounds):
                sig = known + _int_to_hexstr(byt) + unknown
                url = 'http://0.0.0.0:8080/hmac?file={}&sig={}&stime={}'.format(file, sig, 5)

                start = time()
                try:
                    post(url)
                except ConnectionError:  # server isn't running
                    validate_sig(file, sig, 5)
                end = time()
                total += end - start

            avg_runtime = total / rounds
            if avg_runtime > longest:
                longest = avg_runtime
                best = _int_to_hexstr(byt)

        known += best

    return 'Calculated HMAC-SHA1 - {}'.format(known)


def main():
    from main import Solution
    return Solution('32: Break HMAC-SHA1 with a slightly less artificial timing leak', p32)


# BELOW CODE RUNS THE WEBSERVER THAT HANDLES THE POST TO /hmac
if __name__ == '__main__':
    start_server()
