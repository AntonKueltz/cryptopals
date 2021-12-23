from time import time

from main import Solution
from p31 import hmac_sha1, master_key, start_server, validate_sig, use_network

from requests import post


def p32() -> str:
    file = b'secrets.docx'
    expected = hmac_sha1(master_key, file)
    print(f'Calculated HMAC-SHA1 - {expected}')

    rounds = 10
    is_networked = use_network()
    known = b''
    while len(known) < len(expected):
        unknown = (len(expected) - len(known) - 2) * b'?'
        longest, best = 0.0, ''

        for byte in range(0xff + 1):
            total = 0.0

            for _ in range(rounds):
                sig = known + bytes([byte]) + unknown
                url = f'http://0.0.0.0:8080/hmac?file={file}&sig={sig}&sleep={5}'

                start = time()
                if is_networked:
                    post(url)
                else:
                    validate_sig(file, sig, 5)
                end = time()
                total += end - start

            if total > longest:
                longest = total
                best = bytes([byte])

        known += best
        print(known)

    return f'Calculated HMAC-SHA1 - {known}'


def main():
    return Solution('32: Break HMAC-SHA1 with a slightly less artificial timing leak', p32)


# BELOW CODE RUNS THE WEBSERVER THAT HANDLES THE POST TO /hmac
if __name__ == '__main__':
    start_server()
