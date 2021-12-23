from hashlib import sha1
from os import urandom
from time import sleep, time

from main import Solution

from requests import get, post, ConnectionError
from web import application, ctx, input as web_input

urls = (
    '/ping', 'pinger',
    '/hmac', 'hmac_page'
)
master_key = urandom(16)


def hmac_sha1(key: bytes, msg: bytes) -> bytes:
    if len(key) > sha1().block_size:
        key = sha1(key).digest()

    key += b'\x00' * (sha1().block_size - len(key))
    o_key_pad = bytes([c ^ 0x5c for c in key])
    i_key_pad = bytes([c ^ 0x36 for c in key])

    inner = sha1(i_key_pad + msg).digest()
    return sha1(o_key_pad + inner).digest()


def _insecure_compare(sig1: bytes, sig2: bytes, sleep_time: int) -> bool:
    for b1, b2 in zip(sig1, sig2):
        if b1 != b2:
            return False
        sleep(sleep_time / 1000.0)

    return True


def validate_sig(file: bytes, sig: bytes, sleep_time: int) -> bool:
    global master_key
    computed_sig = hmac_sha1(master_key, file)
    return _insecure_compare(sig, computed_sig, sleep_time)


def use_network() -> bool:
    try:
        get('http://0.0.0.0:8080/ping')
        return True
    except ConnectionError:  # server isn't running
        return False


def p31() -> str:
    file = b'secrets.docx'
    expected = hmac_sha1(master_key, file)
    print(f'Calculated HMAC-SHA1 - {expected}')

    is_networked = use_network()
    known = b''
    while len(known) < len(expected):
        unknown = (len(expected) - len(known) - 2) * b'?'
        longest, best = 0.0, b''

        for byte in range(0xff + 1):
            sig = known + bytes([byte]) + unknown
            url = f'http://0.0.0.0:8080/hmac?file={file}&sig={sig}&sleep={50}'

            start = time()
            if is_networked:
                post(url)
            else:
                validate_sig(file, sig, 50)
            end = time()

            runtime = end - start
            if runtime > longest:
                longest = runtime
                best = bytes([byte])

        known += best
        print(known)

    return f'Reconstructed HMAC-SHA1 - {known}'


def main() -> Solution:
    return Solution('31: Implement and break HMAC-SHA1 with an artificial timing leak', p31)


# BELOW CODE IS THE WEBSERVER THAT HANDLES THE POST TO /hmac
def start_server():
    app = application(urls, globals())
    app.run()


class pinger():
    def GET(self) -> str:
        ctx.status = '200 OK'
        return 'explicit 200'


class hmac_page():
    def POST(self) -> str:
        data = web_input()
        valid = validate_sig(data.file, data.sig, data.sleep)

        if valid:
            ctx.status = '200 OK'
            return 'explicit 200'
        else:
            ctx.status = '500 Internal Server Error'
            return 'explicit 500'


if __name__ == '__main__':
    start_server()
