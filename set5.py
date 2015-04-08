import aes_modes
import hash_funcs
import keyex
import padding
import rsa
import srp
import util


def diffie_hellman():
    dh1 = keyex.DiffieHellman()
    dh2 = keyex.DiffieHellman()
    dh1.computeShared(dh2.getA())
    dh2.computeShared(dh1.getA())
    equal = dh1.shared == dh2.shared

    return "Shared Secret Established" if equal else "No Shared Secret :("


def dh_param_injection():
    alice = keyex.DiffieHellman()
    bob = keyex.DiffieHellman()

    bob.computeShared(bob.p)
    alice.computeShared(alice.p)

    sha1 = hash_funcs.SHA1()

    a_msg = 'I hope this doesn\'t get pwned'
    a_iv = util.gen_random_bytes(16)
    a_key = sha1.hash(alice.shared).decode('hex')[:16]
    a_sends = aes_modes.AES_CBC_encrypt(a_msg, a_key, a_iv), a_iv

    e_key = sha1.hash(0).decode('hex')[:16]
    e_msg = aes_modes.AES_CBC_decrypt(a_sends[0], e_key, a_iv)
    e_msg = padding.validate(e_msg)
    if e_msg != a_msg:
        return 'Intercepted Traffic Incorrectly Decrypted :('

    b_iv = util.gen_random_bytes(16)
    b_key = sha1.hash(bob.shared).decode('hex')[:16]
    b_msg = aes_modes.AES_CBC_decrypt(a_sends[0], b_key, a_iv)
    b_msg = padding.validate(b_msg)
    b_sends = aes_modes.AES_CBC_encrypt(b_msg, b_key, b_iv), b_iv

    e_msg = aes_modes.AES_CBC_decrypt(b_sends[0], e_key, b_iv)
    e_msg = padding.validate(e_msg)
    if e_msg != b_msg:
        return 'Intercepted Traffic Incorrectly Decrypted :('

    return 'All Traffic Intercepted And Decrypted!'


def dh_malicious_group():
    p = keyex.DiffieHellman.default_p
    sha1 = hash_funcs.SHA1()

    for g in [1, p, p-1]:
        alice = keyex.DiffieHellman(g=g)
        bob = keyex.DiffieHellman(g=g)

        alice.computeShared(bob.getA())
        bob.computeShared(alice.getA())

        a_msg = 'I hope this doesn\'t get pwned'
        a_iv = util.gen_random_bytes(16)
        a_key = sha1.hash(alice.shared).decode('hex')[:16]
        a_sends = aes_modes.AES_CBC_encrypt(a_msg, a_key, a_iv), a_iv

        if g == 1:
            e_key = sha1.hash(1).decode('hex')[:16]
            e_msg = aes_modes.AES_CBC_decrypt(a_sends[0], e_key, a_iv)
            e_msg = padding.validate(e_msg)
        elif g == p:
            e_key = sha1.hash(0).decode('hex')[:16]
            e_msg = aes_modes.AES_CBC_decrypt(a_sends[0], e_key, a_iv)
            e_msg = padding.validate(e_msg)
        elif g == p-1:
            for e_seed in [1, g, g**2 % p]:
                e_key = sha1.hash(e_seed).decode('hex')[:16]
                e_msg = aes_modes.AES_CBC_decrypt(a_sends[0], e_key, a_iv)
                try:
                    e_msg = padding.validate(e_msg)
                    break
                except:
                    continue

        if e_msg != a_msg:
            return 'Intercepted Traffic Incorrectly Decrypted :( '

        b_iv = util.gen_random_bytes(16)
        b_key = sha1.hash(bob.shared).decode('hex')[:16]
        b_msg = aes_modes.AES_CBC_decrypt(a_sends[0], b_key, a_iv)
        b_msg = padding.validate(b_msg)
        b_sends = aes_modes.AES_CBC_encrypt(b_msg, b_key, b_iv), b_iv

        e_msg = aes_modes.AES_CBC_decrypt(b_sends[0], e_key, b_iv)
        e_msg = padding.validate(e_msg)
        if e_msg != b_msg:
            return 'Intercepted Traffic Incorrectly Decrypted :( '

    return 'All Traffic Intercepted And Decrypted!'


def secure_remote_password():
    email = 'foo@bar.com'
    password = 'password'

    client = srp.Client(email, password)
    server = srp.Server(email, password)
    client.set_server(server)
    server.set_client(client)

    client.initiate()
    return 'Login ' + 'Success' if server.check_hmac() else 'Failure'


def srp_w_zerokey():
    email = 'foo@bar.com'
    password = 'password'
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
    retstr = ''

    for i, badA in enumerate([0, N, N*2]):
        Astr = ['0', 'N', 'N*2']
        client = srp.Client(email, password, tampered=True, A=badA)
        server = srp.Server(email, 'wrongpassword')
        client.set_server(server)
        server.set_client(client)

        client.initiate()
        status = 'Success' if server.check_hmac() else 'Failure'
        retstr += 'Login ' + status + ' [A={}]\n'.format(Astr[i])

    return retstr[:-1]


def basic_rsa():
    r = rsa.RSA()
    m = util.gen_random_bytes(1024 / 8 - 1)
    c = r.enc(m)
    equal = m == r.dec(c)
    return 'RSA Working Properly' if equal else 'Something is Wrong :('


def rsa_broadcast():
    cs = []
    msg = 'This message is secret and unfortunately e is not high. ' \
          'The message should also be sufficiently long so it is a ' \
          'residue.'

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

    return util.int_to_ascii(util.kth_root(c, 3))
