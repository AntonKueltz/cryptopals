from binascii import unhexlify
from os import urandom
from time import sleep, time

from p28 import SHA1

from requests import post, ConnectionError
from web import application, ctx, input as web_input, template

urls = ('/hmac', 'hmac_page')
master_key = urandom(16)


def hmac_sha1(key, msg):
    s = SHA1()
    if len(key) > s.BLOCKSIZE:
        key = s.hash(key)

    key += '\x00' * (s.BLOCKSIZE - len(key))
    o_key_pad = ''.join([chr(ord(c) ^ 0x5c) for c in key])
    i_key_pad = ''.join([chr(ord(c) ^ 0x36) for c in key])

    tmp = s.hash(i_key_pad + msg)
    inner = '0' if len(tmp) & 1 else '' + tmp
    return s.hash(o_key_pad + unhexlify(inner))


def _insecure_compare(sig1, sig2, sleep_time):
    for b1, b2 in zip(unhexlify(sig1), unhexlify(sig2)):
        if b1 != b2:
            return False
        sleep(sleep_time / 1000.0)

    return True


def validate_sig(file, sig, sleep_time):
    global master_key
    file = file.encode('ascii')
    computed_sig = hmac_sha1(master_key, file)
    return _insecure_compare(sig, computed_sig, sleep_time)


def p31():
    def _int_to_hexstr(i):
        s = hex(i).replace('0x', '').replace('L', '')
        return ('0' if len(s) & 1 else '') + s

    file = 'secrets.docx'
    expected = hmac_sha1(master_key, file)
    print 'Calculated HMAC-SHA1 - {}'.format(expected)

    known = ''
    while len(known) < len(expected):
        unknown = (len(expected) - len(known) - 2) * '0'
        longest, best = 0.0, ''

        for byt in range(0xff + 1):
            sig = known + _int_to_hexstr(byt) + unknown
            url = 'http://0.0.0.0:8080/hmac?file={}&sig={}&sleep={}'.format(file, sig, 50)

            start = time()
            try:
                post(url)
            except ConnectionError:  # server isn't running
                validate_sig(file, sig, 50)
            end = time()

            runtime = end - start
            if runtime > longest:
                longest = runtime
                best = _int_to_hexstr(byt)

        known += best

    return 'Calculated HMAC-SHA1 - {}'.format(known)


def main():
    from main import Solution
    return Solution('31: Implement and break HMAC-SHA1 with an artificial timing leak', p31)


# BELOW CODE IS THE WEBSERVER THAT HANDLES THE POST TO /hmac
def start_server():
    app = application(urls, globals())
    app.run()


class hmac_page():
    def POST(self):
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
