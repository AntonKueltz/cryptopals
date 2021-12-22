from p39 import invmod
from p43 import DSA


def p45() -> str:
    dsa = DSA()

    dsa.g = 0
    r, s = dsa.sign(b'Original Message')
    assert dsa.verify(b'Bad Message', r, s)

    dsa.g = dsa.p + 1
    z = 2
    r = pow(dsa.y, z, dsa.p) % dsa.q
    s = (r * invmod(z, dsa.q)) % dsa.q
    assert dsa.verify(b'Hello World', r, s)
    assert dsa.verify(b'Goodbye World', r, s)

    return f'Signature for "Hello World" and "Goodbye World" - ({r}, {s})'


def main():
    from main import Solution
    return Solution('45: DSA parameter tampering', p45)
