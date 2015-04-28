#!/usr/bin/env python
# coding: UTF-8
# author: Markus Döring
# license: GPLv3

import hashlib
import re

from wordlist import wordlist

_mod_desc = """
This module can be used to obfuscate or simply hide ip addresses, e.g.
in server access log files. With a regularly rotated secret, the IPs
remain readable, you can monitor and backtrace the requests of a single
IP (for security auditing, ...) but the actual user IP remains hidden.
""" 

ip_re = re.compile(r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}")


def interleave(*args):
    """
    get an iterator interleaving 1 to n iterables

    >>> list(interleave(range(1, 5)))
    [1, 2, 3, 4]
    >>> list(interleave(range(4), range(5,8)))
    [0, 5, 1, 6, 2, 7, 3]
    >>> list(interleave(range(500), range(5,8)))
    [0, 5, 1, 6, 2, 7, 3]
    """
    n = len(args)
    assert n > 0
    iterators = map(iter, args)
    counter = 0
    while True:
        current_iterator = iterators[counter % n]
        yield current_iterator.next()
        counter += 1

def ip2words(ip):
    """
    transforms an IP to a list of 4 PGP words

    >>> ip2words("1.2.3.4")
    u'absurd.aftermath.acme.alkali'
    >>> ip2words("255.254.255.254")
    u'Zulu.yesteryear.Zulu.yesteryear'
    """
    foo = lambda (i, n): wordlist[n][i%2]
    ips = map(int, ip.split("."))
    words = map(foo, enumerate(ips))
    return ".".join(words)


def rotateip(ip, secret=None):
    """
    rotate ip to another address

    if 'secret' is given, the ip will be
      * salted with secret
      * hashed by SHA-1
      * combined to a new IP
    otherwise, the ip will be rotated to 0.0.0.0

    >>> rotateip("127.0.0.1")
    '0.0.0.0'
    >>> rotateip("127.0.0.1", secret="secret")
    '112.64.123.134'
    >>> x = rotateip("127.0.0.1", secret="secret")
    >>> y = rotateip("127.0.0.1", secret="secret2")
    >>> x == y
    False
    """

    def tokenize(a, n):
        return map(lambda i: a[i:i+n], range(0, len(a), n))

    if secret is None:
        return "0.0.0.0"
    h = hashlib.new("sha256")
    assert h.digest_size == 32
    h.update(ip)
    h.update(secret)
    x = h.hexdigest()
    assert len(x) == 64
    t = tokenize(x, 16)
    tt = map(lambda y: tokenize(y, 2), t)
    tti = map(lambda subtt: map(lambda s: int(s, base=16), subtt), tt)
    ttr = map(lambda subtt: str(sum(subtt) % 256), tti)
    return ".".join(ttr)


def replaceip(line, secret=None, words=True):
    """
    replace all IPs in line using the module functions

    >>> test = "bla 127.0.0.1 blub 255.255.255.255 test"
    >>> replaceip(test, words=False)
    'bla 0.0.0.0 blub 0.0.0.0 test'
    >>> test = "bla 127.0.0.1 blub "
    >>> replaceip(test, secret="secret", words=False)
    'bla 112.64.123.134 blub '
    >>> replaceip(test, secret="secret")
    u'bla guidance.Dakota.kickoff.letterhead blub '
    >>> s = replaceip("192.168.0.1 καὶ 10.10.10.10 δὲν θὰ βρῶ πιὰ στὸ χρυσαφὶ ξέφωτο", words=False)
    >>> print(s)
    0.0.0.0 καὶ 0.0.0.0 δὲν θὰ βρῶ πιὰ στὸ χρυσαφὶ ξέφωτο
    """
    tokens = ip_re.split(line)
    ips = ip_re.findall(line)
    ips = map(lambda ip: rotateip(ip, secret=secret), ips)
    if words:
        ips = map(ip2words, ips)
    out = "".join(interleave(tokens, ips))
    return out

if __name__ == "__main__":
    import argparse
    import sys
    parser = argparse.ArgumentParser(description=_mod_desc)
    parser.add_argument('-i', '--infile',
                        type=argparse.FileType('r'),
                        default=sys.stdin,
                        help="input, read line by line, default: stdin")
    parser.add_argument('-s', '--secret',
                        type=argparse.FileType('r'),
                        default=None,
                        help="secret file for rotating IPs")
    parser.add_argument('-o', '--outfile',
                        type=argparse.FileType('a'),
                        default=sys.stdout,
                        help="output, appended to, default: stdout")
    parser.add_argument('-w', '--words', action="store_true",
                        default=False,
                        help="replace bytes by words, default: False")
    args = parser.parse_args()

    if args.secret is not None:
        secret = args.secret.read()
    else:
        secret = None

    for line in args.infile:
        mod = replaceip(line, secret=secret, words=args.words)
        args.outfile.write(mod)

    args.infile.close()
    args.outfile.close()
