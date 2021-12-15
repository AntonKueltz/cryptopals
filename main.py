#!/usr/bin/env python3

from argparse import ArgumentParser
from importlib import import_module


class Solution:
    def __init__(self, title, solver):
        self.title = title
        self.solver = solver

    def __call__(self):
        print(f'\033[94m[{self.title}]\033[0m')
        result = self.solver()
        result = result.decode() if isinstance(result, bytes) else str(result)
        result = result.rstrip()
        print(f'{result}\n')


def main(set=None, problem=None):
    problems = ['p{:02}'.format(i + 1) for i in range(56)]

    if set is not None:
        set_size = 8
        start = (set - 1) * set_size
        end = start + set_size
        problems = problems[start:end]
    elif problem is not None:
        problems = [problems[problem - 1]]

    for problem in problems:
        module = import_module(problem)
        solution = module.main()
        solution()


if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument('--set', type=int, metavar='SET', help='the set to run')
    parser.add_argument('--problem', type=int, metavar='PROBLEM', help='the problem to run')
    args = parser.parse_args()
    main(set=args.set, problem=args.problem)
