import hashlib
import hmac
import sys
import time

from Crypto.Random import random
import web

import mac
import srp
import util

render = web.template.render('html/')

urls = ('/', 'index', '/hmac', 'hmac_page', '/login', 'login')


def start_server():
    app = web.application(urls, globals())
    app.run()


class index():
    def GET(self):
        return 'Cryptopals Landing Page'


class hmac_page():
    def POST(self):
        data = web.input()
        valid = self.validate_sig(data.file, data.sig, int(data.stime))
        if valid:
            web.ctx.status = '200 OK'
            return 'explicit 200'
        else:
            web.ctx.status = '500 Internal Server Error'
            return 'explicit 500'

    def validate_sig(self, file, sig, stime):
        key = 'YELLOW SUBMARINE'
        file = file.encode('ascii')
        computed_sig = mac.hmac_sha1(key, file)
        return self.insecure_compare(sig, computed_sig, stime)

    def insecure_compare(self, sig1, sig2, stime):
        for b1, b2 in zip(sig1.decode('hex'), sig2.decode('hex')):
            if b1 != b2:
                return False
            time.sleep(stime / 1000.0)

        return True


class login():
    N = int(
        'ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024'
        'e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd'
        '3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec'
        '6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f'
        '24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361'
        'c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552'
        'bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff'
        'fffffffffffff', 16
    )
    g = 2
    k = 3
    passwd = {'foo@bar.com': 'abhorrent'}

    salt, B, K = None, None, None

    def GET(self):
        return '{} {}'.format(login.salt, login.B)

    def POST(self):
        data = web.input()
        keys = data.keys()

        if 'I' in keys and 'A' in keys:
            login.salt = random.randint(0, 2**32-1)
            P = login.passwd[data.I]

            xH = hashlib.sha256(str(login.salt) + P).hexdigest()
            x = int(xH, 16)
            v = util.mod_exp(login.g, x, login.N)

            A = int(data.A)
            b = random.randint(0, login.N-1)
            exp_term = util.mod_exp(login.g, b, login.N)
            login.B = (login.k * v + exp_term) % login.N

            uH = hashlib.sha256(str(A) + str(login.B)).hexdigest()
            u = int(uH, 16)

            base = A * util.mod_exp(v, u, self.N) % self.N
            S = util.mod_exp(base, b, login.N)
            login.K = hashlib.sha256(str(S)).hexdigest()

        elif 'hmac' in keys:
            raw_hmac = hmac.new(login.K, str(login.salt), hashlib.sha256)
            server_hmac = raw_hmac.hexdigest()
            client_hmac = str(data.hmac)

            mac_equal = False
            if sys.version_info < (2, 7, 7):
                # DONT EVER DO THIS IN REAL CODE
                mac_equal = client_hmac == server_hmac
            else:
                mac_equal = hmac.compare_digest(client_hmac, server_hmac)

            if mac_equal:
                web.ctx.status = '200 OK'
                return 'explicit 200'
            else:
                web.ctx.status = '403 Forbidden'
                return 'explicit 403'


if __name__ == '__main__':
    start_server()
