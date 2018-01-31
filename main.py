#!/usr/bin/env python3
# coding: UTF-8
# author: Markus Rudy
# license: GPLv3

import time
import sys
import os
import logging

import hideip

_SALT_SIZE = 32

logging.basicConfig()

_mod_desc = """
This module can be used to obfuscate or simply hide ip addresses, e.g.
in server access log files. With a regularly rotated secret, the IPs
remain readable, you can monitor and backtrace the requests of a single
IP (for security auditing, ...) but the actual user IP remains hidden.
"""


def mainloop(args):
    secret = b"" if args.secret else None
    last_updated = float("NaN")

    for line in args.infile:
        t = time.monotonic()

        # invert predicate to make use of NaN semantics
        if secret is not None and not t - last_updated < args.time:
            logging.info("Updating the salt ...")
            secret = os.urandom(_SALT_SIZE)
            last_updated = t

        try:
            mod = hideip.replaceip(line, salt=secret, words=args.words)
            args.outfile.write(mod)
            args.outfile.flush()
        except Exception as e:
            logging.error("swallowing an error: %s", repr(e))


if __name__ == "__main__":
    import argparse
    import sys
    parser = argparse.ArgumentParser(description=_mod_desc)
    parser.add_argument('-i', '--infile',
                        type=argparse.FileType('r'),
                        default=sys.stdin,
                        help="input, read line by line, default: stdin")
    parser.add_argument('-s', '--secret', default=False, action="store_true",
                        help="generate pseudonyms (default: set IP to 0.0.0.0)")
    parser.add_argument('-o', '--outfile',
                        type=argparse.FileType('a'),
                        default=sys.stdout,
                        help="output, appended to, default: stdout")
    parser.add_argument('-w', '--words', action="store_true",
                        default=False,
                        help="replace bytes by words, default: False")
    parser.add_argument('-t', '--time', action="store", type=str,
                        default="60m",
                        help="validity period of salt <amount>(s|m|d), "
                             "default: 60m")
    args = parser.parse_args()

    try:
        args.time = hideip.parse_time(args.time)
    except:
        sys.stderr.write("Could not parse option '-t'\n")
        sys.exit(1)

    try:
        mainloop(args)
    finally:
        args.infile.close()
        args.outfile.close()
