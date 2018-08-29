from Crypto.Random.random import randint


class DiffieHellman():
    default_p = int(
        'ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024'
        'e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd'
        '3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec'
        '6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f'
        '24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361'
        'c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552'
        'bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff'
        'fffffffffffff', 16
    )

    def __init__(self, p=default_p, g=2):
        self.p = p
        self.g = g
        self.secret = randint(0, p-1)
        self.public = pow(g, self.secret, p)
        self.shared = None

    def derive_shared_secret(self, B):
        self.shared = pow(B, self.secret, self.p)


def p33():
    print 'Using DH params p=37 g=5'
    alice = DiffieHellman(p=37, g=5)
    bob = DiffieHellman(p=37, g=5)

    print 'Alice\'s DH keys are\n  public: {}\n  secret: {}'.format(alice.public, alice.secret)
    print 'Bob\'s DH keys are\n  public: {}\n  secret: {}'.format(bob.public, bob.secret)

    alice.derive_shared_secret(bob.public)
    bob.derive_shared_secret(alice.public)
    return 'Alice derived {}\nBob derived {}'.format(alice.shared, bob.shared)


def main():
    from main import Solution
    return Solution('33: Implement Diffie-Hellman', p33)
