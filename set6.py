import rsa
import util


def rsa_recovery_oracle():
    r = rsa.RSA()
    N, e = r.n, r.e

    ptxt = raw_input('Enter some text: ')
    ctxt = r.enc(ptxt)

    s = 2
    ctxt_ = util.mod_exp(s, e, N) * ctxt % N
    ascii_ptxt = r.dec(ctxt_)
    ptxt_ = int(ascii_ptxt.encode('hex'), 16)

    return util.int_to_ascii(util.mod_inv(s, N) * ptxt_ % N)
