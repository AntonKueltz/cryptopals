import keyex
import rsa
import util


def diffie_hellman():
    p = int(
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

    dh1 = keyex.DiffieHellman(p, g)
    dh2 = keyex.DiffieHellman(p, g)
    dh1.computeShared(dh2.getA())
    dh2.computeShared(dh1.getA())
    equal = dh1.shared == dh2.shared

    return "Shared Secret Established" if equal else "No Shared Secret :("


def basic_rsa():
    r = rsa.RSA()
    m = util.gen_random_bytes(1024 / 8 - 1)
    c = r.enc(m)
    equal = m == r.dec(c)
    return 'RSA Working Properly' if equal else 'Something is Wrong :('


def rsa_broadcast():
    cs = []
    msg = 'This message is secret and unfortunately e is not high.' \
          'The message should also be sufficiently long so it is a' \
          ' residue.'

    for _ in range(3):
        r = rsa.RSA()
        c = r.enc(msg)
        cs.append((c, r.n))

    c0, c1, c2 = cs[0][0], cs[1][0], cs[2][0]
    n0, n1, n2 = cs[0][1], cs[1][1], cs[2][1]
    m0, m1, m2 = n1 * n2, n0 * n2, n0 * n1

    t0 = (c0 * m0 * util.mod_inv(m0, n0))
    t1 = (c1 * m1 * util.mod_inv(m1, n1))
    t2 = (c2 * m2 * util.mod_inv(m2, n2))
    c = (t0 + t1 + t2) % (n0*n1*n2)

    raw = hex(util.kth_root(c, 3))[2:-1]
    return (('0' if len(raw) & 1 else '') + raw).decode('hex')
