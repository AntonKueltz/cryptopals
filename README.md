# cryptopals
Solutions for the [Matasano Crypto Challenges](http://cryptopals.com).

## usage
This code is currently only python3.6+ compatible. To run it install all dependencies

```bash
pip install -r requirements  # method 1
pip install pycryptodome requests web.py  # method 2
```

Then use `python main.py` to run individual problems, individual sets, or all problems

```bash
$ python main.py --help
usage: main.py [-h] [--set SET] [--problem PROBLEM]

optional arguments:
  -h, --help         show this help message and exit
  --set SET          the set to run
  --problem PROBLEM  the problem to run
 ```

Some problems (30, 31, 36, 37, 38) involve running a server. This server can be run by
executing the python file relating to the problem, e.g. to run problem 30 with a server

```bash
# in terminal 1
python p30.py
# in terminal 2
python main --problem 30
```

When you run the problem in terminal 2 you'll see the requests being made in terminal 1.
If you prefer to not run a server the problems will default to using function calls that
mimic calling an actual server.

## progress
* Set 1 ✓ [8/8 complete]
* Set 2 ✓ [8/8 complete]
* Set 3 ✓ [8/8 complete]
* Set 4 ✓ [8/8 complete]
* Set 5 ✓ [8/8 complete]
* Set 6 ✓ [8/8 complete]
* Set 7 ✓ [8/8 complete]
* Set 8 ? [REDACTED]
