from hashlib import sha256
from hmac import compare_digest, new as new_hmac
from os import urandom
from typing import Dict

from main import Solution
from p33 import DiffieHellman

from Crypto.Random.random import randint
from requests import ConnectionError, post
from web import application, ctx, input as web_input

urls = ('/login', 'login', )


class Server:
    class Response:
        def __init__(self, code):
            self.status_code = code

    """Simulates a server if you don't want to run one"""
    passwd = {'foo@bar.com': 'abhorrentaardvark'}
    N = DiffieHellman.default_p
    g, k = 2, 3
    salt, K = b'', b''

    def get_client_ids(self, I: str, A: int) -> Dict:
        self.salt = urandom(4)
        P = Server.passwd[I]

        xh = sha256(self.salt + P.encode()).hexdigest()
        x = int(xh, 16)
        v = pow(Server.g, x, Server.N)

        b = randint(0, Server.N - 1)
        exp_term = pow(Server.g, b, Server.N)
        B = (Server.k * v + exp_term) % Server.N

        uh = sha256(str(A).encode() + str(B).encode()).hexdigest()
        u = int(uh, 16)

        base = A * pow(v, u, Server.N) % Server.N
        S = pow(base, b, Server.N)
        self.K = sha256(str(S).encode()).digest()

        return {'salt': self.salt, 'B': B}

    def check_hmac(self, client_hmac: str) -> Response:
        raw_hmac = new_hmac(self.K, self.salt, sha256)
        server_hmac = raw_hmac.hexdigest()
        mac_equal = compare_digest(client_hmac, server_hmac)

        if mac_equal:
            return self.Response(200)
        else:
            return self.Response(403)


def p36() -> str:
    server = Server()
    base_url = 'http://0.0.0.0:8080/login'

    N = DiffieHellman.default_p
    g, k = 2, 3
    I, P = 'foo@bar.com', 'abhorrentaardvark'

    a = 0xdecafbad  # randint(0, N - 1)
    A = pow(g, a, N)

    print('Sending I and A to server...')
    try:
        args = '?I={}&A={}'.format(I, A)
        response = post(base_url + args)
        response_content = eval(response.content)
    except ConnectionError:
        response_content = server.get_client_ids(I, A)

    salt, B = response_content.get('salt'), response_content.get('B')
    print(f'Server responded with salt = {salt} and B = {str(B)[:20]}...')

    uh = sha256(str(A).encode() + str(B).encode()).hexdigest()
    u = int(uh, 16)
    xh = sha256(salt + P.encode()).hexdigest()
    x = int(xh, 16)

    base = B - k * pow(g, x, N)
    exp = a + u * x
    S = pow(base, exp, N)

    K = sha256(str(S).encode()).digest()
    print(f'Client computed K = {K[:20]}...')
    client_hmac = new_hmac(K, salt, sha256).hexdigest()

    print('Sending HMAC to server...')
    try:
        args = '?hmac={}'.format(client_hmac)
        response = post(base_url + args)
    except ConnectionError:
        response = server.check_hmac(client_hmac)

    if response.status_code != 200:
        return 'Server responded with "403 Forbidden"'

    return 'Server responded with "200 OK"'


def main() -> Solution:
    return Solution('36: Implement Secure Remote Password (SRP)', p36)


# BELOW CODE IS THE WEBSERVER THAT HANDLES CLIENT SRP REQUESTS
class login():
    N = DiffieHellman.default_p
    g, k = 2, 3
    passwd = {'foo@bar.com': 'abhorrentaardvark'}
    salt, B, K = None, None, None

    def POST(self) -> str:
        data = web_input()
        keys = data.keys()

        if 'I' in keys and 'A' in keys:
            login.salt = urandom(4)
            P = login.passwd[data.I]

            xh = sha256(login.salt + P.encode()).hexdigest()
            x = int(xh, 16)
            v = pow(login.g, x, login.N)

            A = int(data.A)
            b = randint(0, Server.N - 1)
            exp_term = pow(login.g, b, login.N)
            B = (login.k * v + exp_term) % login.N

            uh = sha256(str(A).encode() + str(B).encode()).hexdigest()
            u = int(uh, 16)

            base = A * pow(v, u, self.N) % self.N
            S = pow(base, b, login.N)
            login.K = sha256(str(S).encode()).digest()

            return str({'salt': login.salt, 'B': B})

        elif 'hmac' in keys:
            raw_hmac = new_hmac(login.K, login.salt, sha256)
            server_hmac = raw_hmac.hexdigest()
            mac_equal = compare_digest(data.hmac, server_hmac)

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
