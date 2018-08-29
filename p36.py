from hashlib import sha256
from hmac import compare_digest, new as new_hmac
from json import dumps, loads

from p33 import DiffieHellman

from Crypto.Random.random import getrandbits, randint
from requests import ConnectionError, post
from web import application, ctx, input as web_input

urls = ('/login', 'login', )


class Server:
    """Simulates a server if you don't want to run one"""
    passwd = {'foo@bar.com': 'abhorrentaardvark'}
    N = DiffieHellman.default_p
    g, k = 2, 3

    def get_client_ids(self, I, A):
        self.salt = getrandbits(32)
        P = Server.passwd[I]

        xH = sha256(str(self.salt) + P).hexdigest()
        x = int(xH, 16)
        v = pow(Server.g, x, Server.N)

        b = randint(0, Server.N - 1)
        exp_term = pow(Server.g, b, Server.N)
        B = (Server.k * v + exp_term) % Server.N

        uH = sha256(str(A) + str(B)).hexdigest()
        u = int(uH, 16)

        base = A * pow(v, u, Server.N) % Server.N
        S = pow(base, b, Server.N)
        self.K = sha256(str(S)).hexdigest()

        return {'salt': self.salt, 'B': B}

    def check_hmac(self, client_hmac):
        class Response:
            def __init__(self, code):
                self.status_code = code

        raw_hmac = new_hmac(self.K, str(self.salt), sha256)
        server_hmac = raw_hmac.hexdigest()
        mac_equal = compare_digest(client_hmac, server_hmac)

        if mac_equal:
            return Response(200)
        else:
            return Response(403)


def p36():
    server = Server()
    base_url = 'http://0.0.0.0:8080/login'

    N = DiffieHellman.default_p
    g, k = 2, 3
    I, P = 'foo@bar.com', 'abhorrentaardvark'

    a = randint(0, N - 1)
    A = pow(g, a, N)

    print 'Sending I and A to server...'
    try:
        args = '?I={}&A={}'.format(I, A)
        response = post(base_url + args)
        response_content = loads(response.content)
    except ConnectionError:
        response_content = server.get_client_ids(I, A)

    salt, B = response_content.get('salt'), response_content.get('B')
    print 'Server responded with salt = {} and B = {}...'.format(salt, str(B)[:20])

    uH = sha256(str(A) + str(B)).hexdigest()
    u = int(uH, 16)
    xH = sha256(str(salt) + str(P)).hexdigest()
    x = int(xH, 16)

    base = B - k * pow(g, x, N)
    exp = a + u * x
    S = pow(base, exp, N)

    K = sha256(str(S)).hexdigest()
    print 'Client computed K = {}...'.format(K[:20])
    client_hmac = new_hmac(K, str(salt), sha256).hexdigest()

    print 'Sending HMAC to server...'
    try:
        args = '?hmac={}'.format(client_hmac)
        response = post(base_url + args)
    except ConnectionError:
        response = server.check_hmac(client_hmac)

    if response.status_code != 200:
        return 'Server responded with "403 Forbidden"'

    return 'Server responded with "200 OK"'


def main():
    from main import Solution
    return Solution('36: Implement Secure Remote Password (SRP)', p36)


# BELOW CODE IS THE WEBSERVER THAT HANDLES CLIENT SRP REQUESTS
class login():
    N = DiffieHellman.default_p
    g, k = 2, 3
    passwd = {'foo@bar.com': 'abhorrentaardvark'}
    salt, B, K = None, None, None

    def POST(self):
        data = web_input()
        keys = data.keys()

        if 'I' in keys and 'A' in keys:
            login.salt = getrandbits(32)
            P = login.passwd[data.I]

            xH = sha256(str(login.salt) + P).hexdigest()
            x = int(xH, 16)
            v = pow(login.g, x, login.N)

            A = int(data.A)
            b = randint(0, login.N-1)
            exp_term = pow(login.g, b, login.N)
            B = (login.k * v + exp_term) % login.N

            uH = sha256(str(A) + str(login.B)).hexdigest()
            u = int(uH, 16)

            base = A * pow(v, u, self.N) % self.N
            S = pow(base, b, login.N)
            login.K = sha256(str(S)).hexdigest()

            return dumps({'salt': login.salt, 'B': B})

        elif 'hmac' in keys:
            raw_hmac = new_hmac(login.K, str(login.salt), sha256)
            server_hmac = raw_hmac.hexdigest()
            client_hmac = str(data.hmac)
            mac_equal = compare_digest(client_hmac, server_hmac)

            if mac_equal:
                ctx.status = '200 OK'
                return 'explicit 200'
            else:
                ctx.status = '403 Forbidden'
                return 'explicit 403'


def start_server():
    app = application(urls, globals())
    app.run()


if __name__ == '__main__':
    start_server()
