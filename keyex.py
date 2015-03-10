import random  # TODO change later?

import util


class DiffieHellman():
    def __init__(self, p, g):
        self.p = p
        self.g = g
        self.secret = random.randint(0, p-1)
        self.shared = None

    def getA(self):
        return util.mod_exp(self.g, self.secret, self.p)

    def computeShared(self, B):
        aB = util.mod_exp(B, self.secret, self.p)
        self.shared = aB
