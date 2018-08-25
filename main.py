from argparse import ArgumentParser
from importlib import import_module


class Solution:
    def __init__(self, title, solver):
        self.title = title
        self.solver = solver

    def __call__(self):
        print '\033[94m[' + self.title + ']\033[0m'
        result = str(self.solver()).rstrip()
        print result + '\n'


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
    parser.add_argument('--set', type=int, metavar='SET_NUM', help='the set to run')
    parser.add_argument('--problem', type=int, metavar='PROBLEM_NUM', help='the problem to run')
    args = parser.parse_args()
    main(set=args.set, problem=args.problem)
