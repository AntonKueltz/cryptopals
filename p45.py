from p39 import invmod
from p43 import DSA


def p45():
    dsa = DSA()

    dsa.g = 0
    r, s = dsa.sign('Original Message')
    assert dsa.verify('Bad Message', r, s)

    dsa.g = dsa.p + 1
    z = 2
    r = pow(dsa.y, z, dsa.p) % dsa.q
    s = (r * invmod(z, dsa.q)) % dsa.q
    assert dsa.verify('Hello World', r, s)
    assert dsa.verify('Goodbye World', r, s)

    return 'Signature for "Hello World" and "Goodbye World" - ({}, {})'.format(r, s)


def main():
    from main import Solution
    return Solution('45: DSA parameter tampering', p45)
