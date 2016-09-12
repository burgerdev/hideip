#!/usr/bin/env python3
# coding: UTF-8
# author: Markus Döring
# license: GPLv3

import os
import hashlib
import re
import logging
import itertools

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
    iterators = [iter(arg) for arg in args]
    counter = 0
    while True:
        current_iterator = iterators[counter % n]
        yield next(current_iterator)
        counter += 1


def ip2words(ip):
    """
    transforms an IP to a list of 4 PGP words

    >>> ip2words("1.2.3.4")
    'absurd.aftermath.acme.alkali'
    >>> ip2words("255.254.255.254")
    'Zulu.yesteryear.Zulu.yesteryear'
    """
    def get_pgp_word_alternating_case(count_and_index):
        count, index = count_and_index
        return wordlist[index][count%2]
    ips = map(int, ip.split("."))
    words = map(get_pgp_word_alternating_case, zip(itertools.count(), ips))
    return ".".join(words)


def rotateip(ip, secret=None, string_fmt="utf-8"):
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
    h.update(ip.encode(string_fmt))
    h.update(secret.encode(string_fmt))
    x = h.hexdigest()
    assert len(x) == 64

    # list of 4 substrings of hex
    tokens = tokenize(x, 16)

    def handle_part(p):
        split = tokenize(p, 2)
        as_int = map(lambda s: int(s, base=16), split)
        reduced = sum(as_int) % 256
        return reduced

    as_ip_tuple = map(handle_part, tokens)
    as_str_ip_tuple = map(str, as_ip_tuple)
    return ".".join(as_str_ip_tuple)


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
    'bla guidance.Dakota.kickoff.letterhead blub '
    >>> s = replaceip("192.168.0.1 καὶ 10.10.10.10 δὲν θὰ βρῶ πιὰ στὸ χρυσαφὶ ξέφωτο", words=False)
    >>> print(s)
    0.0.0.0 καὶ 0.0.0.0 δὲν θὰ βρῶ πιὰ στὸ χρυσαφὶ ξέφωτο
    """
    tokens = ip_re.split(line)
    ips = map(lambda m: m.group(0), ip_re.finditer(line))
    ips = map(lambda ip: rotateip(ip, secret=secret), ips)
    if words:
        ips = map(ip2words, ips)
    out = "".join(interleave(tokens, ips))
    return out


def updateSecret(filename, lastaccess=None, secret=None):
    """
    reload the secret file if it was modified
    """
    if filename is None:
        return None, None

    newaccess = os.path.getmtime(filename)
    if lastaccess is None or newaccess > lastaccess:
        # never read before
        lastaccess = newaccess
        with open(filename, 'rb') as f:
            secret = f.read()

    return lastaccess, secret


def mainloop(args):
    lastaccess, secret = updateSecret(args.secret)

    for line in args.infile:
        if args.keep_reading:
            lastaccess, secret = updateSecret(args.secret,
                                              lastaccess=lastaccess,
                                              secret=secret)
        try:
            mod = replaceip(line, secret=secret, words=args.words)
            args.outfile.write(mod)
            args.outfile.flush()
        except Exception as e:
            logging.error("an error occurred: {}", str(e))


if __name__ == "__main__":
    import argparse
    import sys
    parser = argparse.ArgumentParser(description=_mod_desc)
    parser.add_argument('-i', '--infile',
                        type=argparse.FileType('r'),
                        default=sys.stdin,
                        help="input, read line by line, default: stdin")
    parser.add_argument('-s', '--secret',
                        action="store", default=None,
                        help="secret file for rotating IPs"
                             " (should contain more than 64 byte)")
    parser.add_argument('-o', '--outfile',
                        type=argparse.FileType('a'),
                        default=sys.stdout,
                        help="output, appended to, default: stdout")
    parser.add_argument('-w', '--words', action="store_true",
                        default=False,
                        help="replace bytes by words, default: False")
    parser.add_argument('-k', '--keep-reading', action="store_true",
                        default=False,
                        help="keep reading the secret file, "
                             "default: False")
    args = parser.parse_args()

    try:
        mainloop(args)
    finally:
        args.infile.close()
        args.outfile.close()
