from hashlib import sha256
from hmac import compare_digest, new as new_hmac
from json import dumps, loads

from p33 import DiffieHellman

from Crypto.Random.random import getrandbits, randint
from requests import ConnectionError, post
from web import application, ctx, input as web_input

urls = ('/login/simplified', 'login', )


class Server:
    """Simulates a server if you don't want to run one"""
    N = DiffieHellman.default_p
    g = 2

    def get_client_ids(self, I, A):
        self.salt = getrandbits(32)
        self.A = A

        self.b = randint(0, Server.N - 1)
        B = pow(login.g, self.b, Server.N)

        self.u = getrandbits(128)
        return {'salt': self.salt, 'B': B, 'u': self.u}

    def check_hmac(self, client_hmac):
        with open('/usr/share/dict/words') as f:
            words = f.read().split('\n')

        for guess in words:
            xH = sha256(str(self.salt) + guess).hexdigest()
            x = int(xH, 16)
            v = pow(Server.g, x, Server.N)

            base = self.A * pow(v, self.u, Server.N)
            S = pow(base, self.b, Server.N)
            K = sha256(str(S)).hexdigest()

            raw_hmac = new_hmac(K, str(self.salt), sha256)
            server_hmac = raw_hmac.hexdigest()

            if compare_digest(client_hmac, server_hmac):
                return {'password': guess}


def p38():
    server = Server()
    base_url = 'http://0.0.0.0:8080/login/simplified'

    N = DiffieHellman.default_p
    g = 2
    I, P = 'foo@bar.com', 'abhorrent'

    a = randint(0, N - 1)
    A = pow(g, a, N)

    print 'Sending I and A to server...'
    try:
        args = '?I={}&A={}'.format(I, A)
        response = post(base_url + args)
        content = loads(response.content)
    except ConnectionError:
        content = server.get_client_ids(I, A)

    salt, B, u = content.get('salt'), content.get('B'), content.get('u')
    print 'Server responded with salt = {} and B = {}... u = {}'.format(salt, str(B)[:20], u)

    xH = sha256(str(salt) + str(P)).hexdigest()
    x = int(xH, 16)
    S = pow(B, (a + u * x), N)
    K = sha256(str(S)).hexdigest()
    print 'Client computed K = {}...'.format(K[:20])
    client_hmac = new_hmac(K, str(salt), sha256).hexdigest()

    print 'Sending HMAC to server...'
    try:
        args = '?hmac={}'.format(client_hmac)
        response = post(base_url + args)
    except ConnectionError:
        response = server.check_hmac(client_hmac)

    return 'User password is {}'.format(response.get('password'))


def main():
    from main import Solution
    return Solution('38: Offline dictionary attack on simplified SRP', p38)


# BELOW CODE IS THE WEBSERVER THAT HANDLES CLIENT SRP REQUESTS
class login():
    N = DiffieHellman.default_p
    g = 2
    salt, A, b, u = None, None, None, None

    def POST(self):
        data = web_input()
        keys = data.keys()

        if 'I' in keys and 'A' in keys:
            login.salt = getrandbits(32)

            login.A = int(data.A)
            login.b = randint(0, login.N-1)
            B = pow(login.g, login.b, login.N)

            login.u = getrandbits(128)
            return dumps({'salt': login.salt, 'B': B, 'u': login.u})

        elif 'hmac' in keys:
            with open('/usr/share/dict/words') as f:
                words = f.read().split('\n')

            for guess in words:
                xH = sha256(str(login.salt) + guess).hexdigest()
                x = int(xH, 16)
                v = pow(login.g, x, login.N)

                base = login.A * pow(v, login.u, login.N)
                S = pow(base, login.b, login.N)
                K = sha256(str(S)).hexdigest()
                print 'Server computed K = {}...'.format(K[:20])

                raw_hmac = new_hmac(K, str(login.salt), sha256)
                server_hmac = raw_hmac.hexdigest()
                client_hmac = str(data.hmac)
                if compare_digest(client_hmac, server_hmac):
                    return dumps({'password': guess})


def start_server():
    app = application(urls, globals())
    app.run()


if __name__ == '__main__':
    start_server()
