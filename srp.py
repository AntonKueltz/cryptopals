import hashlib
import hmac

from Crypto.Random import random

import util


class Client(object):
    def __init__(self, email, password, tampered=False, A=None):
        self.N = int(
            'ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024'
            'e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd'
            '3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec'
            '6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f'
            '24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361'
            'c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552'
            'bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff'
            'fffffffffffff', 16
        )
        self.g = 2
        self.k = 3
        self.I = email
        self.P = password
        self.tampered = tampered
        self.badA = A

    def set_server(self, server):
        self.server = server

    def initiate(self):
        self.a = random.randint(0, self.N-1)

        if self.tampered:
            self.A = self.badA
        else:
            self.A = util.mod_exp(self.g, self.a, self.N)

        self.server.get_A(self.I, self.A)

    def get_B(self, salt, B):
        self.salt = salt
        uH = hashlib.sha256(str(self.A) + str(B)).hexdigest()
        u = int(uH, 16)
        xH = hashlib.sha256(str(salt) + self.P).hexdigest()
        x = int(xH, 16)

        base = B - self.k * util.mod_exp(self.g, x, self.N)
        exp = self.a + u * x
        S = util.mod_exp(base, exp, self.N)

        if self.tampered:
            self.K = hashlib.sha256(str(0)).hexdigest()
        else:
            self.K = hashlib.sha256(str(S)).hexdigest()

    def get_hmac(self):
        return hmac.new(self.K, str(self.salt), hashlib.sha256).hexdigest()


class Server(object):
    def __init__(self, email, password):
        self.N = int(
            'ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024'
            'e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd'
            '3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec'
            '6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f'
            '24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361'
            'c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552'
            'bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff'
            'fffffffffffff', 16
        )
        self.g = 2
        self.k = 3
        self.I = email
        self.P = password
        self.compute_v()

    def set_client(self, client):
        self.client = client

    def compute_v(self):
        self.salt = random.randint(0, 2**32-1)
        xH = hashlib.sha256(str(self.salt) + self.P).hexdigest()
        x = int(xH, 16)
        self.v = util.mod_exp(self.g, x, self.N)

    def get_A(self, I, A):
        self.b = random.randint(0, self.N-1)
        B = (self.k*self.v + (util.mod_exp(self.g, self.b, self.N))) % self.N
        self.client.get_B(self.salt, B)

        uH = hashlib.sha256(str(A) + str(B)).hexdigest()
        u = int(uH, 16)

        base = A * util.mod_exp(self.v, u, self.N) % self.N
        S = util.mod_exp(base, self.b, self.N)
        self.K = hashlib.sha256(str(S)).hexdigest()

    def check_hmac(self):
        hmac_sha256 = hmac.new(self.K, str(self.salt), hashlib.sha256)
        server_hmac = hmac_sha256.hexdigest()
        client_hmac = self.client.get_hmac()
        return hmac.compare_digest(client_hmac, server_hmac)


class SimpleClient(object):
    def __init__(self, email, password):
        self.N = int(
            'ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024'
            'e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd'
            '3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec'
            '6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f'
            '24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361'
            'c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552'
            'bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff'
            'fffffffffffff', 16
        )
        self.g = 2
        self.I = email
        self.P = password

    def set_server(self, server):
        self.server = server

    def initiate(self):
        self.a = random.randint(0, self.N-1)
        self.A = util.mod_exp(self.g, self.a, self.N)
        self.server.get_A(self.I, self.A)

    def get_B(self, salt, B, u):
        self.salt = salt
        xH = hashlib.sha256(str(salt) + self.P).hexdigest()
        x = int(xH, 16)
        S = util.mod_exp(B, (self.a + u*x), self.N)
        self.K = hashlib.sha256(str(S)).hexdigest()

    def get_hmac(self):
        return hmac.new(self.K, str(self.salt), hashlib.sha256).hexdigest()


class MITMServer(object):
    def __init__(self, email, password):
        self.N = int(
            'ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024'
            'e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd'
            '3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec'
            '6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f'
            '24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361'
            'c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552'
            'bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff'
            'fffffffffffff', 16
        )
        self.g = 2
        self.I = email
        self.P = password
        self.compute_v()

    def set_client(self, client):
        self.client = client

    def compute_v(self):
        self.salt = random.randint(0, 2**32-1)
        xH = hashlib.sha256(str(self.salt) + self.P).hexdigest()
        x = int(xH, 16)
        self.v = util.mod_exp(self.g, x, self.N)

    def get_A(self, I, A):
        self.A = A
        self.b = random.randint(0, self.N-1)
        self.B = util.mod_exp(self.g, self.b, self.N)
        self.u = random.getrandbits(128)
        self.client.get_B(self.salt, self.B, self.u)
        base = self.A * util.mod_exp(self.v, self.u, self.N) % self.N
        S = util.mod_exp(base, self.b, self.N)
        self.K = hashlib.sha256(str(S)).hexdigest()

    def break_password(self):
        f = open('/usr/share/dict/words')
        guess = f.readline().strip()
        client_hmac = self.client.get_hmac()

        while guess:
            xH = hashlib.sha256(str(self.salt) + guess).hexdigest()
            x = int(xH, 16)
            v = util.mod_exp(self.g, x, self.N)

            base = self.A * util.mod_exp(v, self.u, self.N) % self.N
            S = util.mod_exp(base, self.b, self.N)
            K = hashlib.sha256(str(S)).hexdigest()

            hmac_sha256 = hmac.new(K, str(self.salt), hashlib.sha256)
            server_hmac = hmac_sha256.hexdigest()

            if hmac.compare_digest(client_hmac, server_hmac):
                f.close()
                return 'Password Cracked: {}'.format(guess)
            else:
                guess = f.readline().strip()

        f.close()
        return 'Password Not In Dictionary!'
