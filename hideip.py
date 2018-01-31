#!/usr/bin/env python3
# coding: UTF-8
# author: Markus Döring
# license: GPLv3

import re
import logging
import itertools

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

from wordlist import wordlist


_IP_RE = re.compile(r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}")
_TIME_RE = re.compile(r"([0-9]+)([smhd])")
_TIME_UNITS = {'s': 1, 'm': 60, 'h': 60*60, 'd': 24*60*60}


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


def rotateip(ip, salt=None):
    """
    rotate ip to another address

    if 'salt' is given, the ip will be
      * salted with secret
      * hashed with SHA-256
      * combined to a new IP
    otherwise, the ip will be rotated to 0.0.0.0

    >>> rotateip("127.0.0.1")
    '0.0.0.0'
    >>> x = rotateip("127.0.0.1", salt=b"secret")
    >>> y = rotateip("127.0.0.1", salt=b"secret2")
    >>> x == y
    False
    """

    def tokenize(a, n):
        return map(lambda i: a[i:i+n], range(0, len(a), n))

    def xor(t):
        x, y = t
        return x ^ y

    if salt is None:
        return "0.0.0.0"

    hkdf = HKDF(algorithm=hashes.SHA256(), length=8, salt=salt,
                info=b"ip-hashing", backend=default_backend())

    hashed = hkdf.derive(ip.encode())

    # for some reason, minimum derived key size is 8, so we need to further
    # reduce the key
    hashed = map(xor, zip(*tokenize(hashed, 4)))

    return ".".join(map(str, hashed))


def replaceip(line, salt=None, words=True):
    """
    replace all IPs in line using the module functions

    >>> test = "bla 127.0.0.1 blub 255.255.255.255 test"
    >>> replaceip(test, words=False)
    'bla 0.0.0.0 blub 0.0.0.0 test'
    >>> test = "bla 127.0.0.1 blub "
    >>> replaceip(test, salt=b"secret", words=False)
    'bla 244.149.186.82 blub '
    >>> replaceip(test, salt=b"secret")
    'bla upshot.Montana.shadow.enrollment blub '
    >>> s = replaceip("192.168.0.1 καὶ 10.10.10.10 δὲν θὰ βρῶ πιὰ στὸ χρυσαφὶ ξέφωτο", words=False)
    >>> print(s)
    0.0.0.0 καὶ 0.0.0.0 δὲν θὰ βρῶ πιὰ στὸ χρυσαφὶ ξέφωτο
    """
    tokens = _IP_RE.split(line)
    ips = map(lambda m: m.group(0), _IP_RE.finditer(line))
    ips = map(lambda ip: rotateip(ip, salt=salt), ips)
    if words:
        ips = map(ip2words, ips)
    out = "".join(interleave(tokens, ips))
    return out


def parse_time(s):
    t, u = _TIME_RE.match(s).groups()

    return int(t) * _TIME_UNITS[u]
