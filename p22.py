from random import randint
from time import sleep, time

from main import Solution
from p21 import MersenneTwister


def p22() -> str:
    wait = randint(40, 100)
    sleep(wait)

    seed = int(time())
    print(f'Seeded MT with value {seed}')
    mt = MersenneTwister(seed)

    wait = randint(40, 100)
    sleep(wait)
    observed_out = mt.extract()

    guess = 0
    guess_seed = int(time()) + 1

    while guess != observed_out:
        guess_seed -= 1
        mt_ = MersenneTwister(guess_seed)
        guess = mt_.extract()

    return f'Recovered seed {guess_seed}'


def main() -> Solution:
    return Solution('22: Crack an MT19937 seed', p22)
