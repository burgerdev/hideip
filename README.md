hideip
======

Command line tool to obfuscate IP addresses in log files, securely. The
IP addresses are hashed and recombined to new IP addresses, so that they
are still distinguishable but can't be associated with a user's real IP.
If the secret salt is long enough (e.g. larger than 64 bytes), the
obfuscation should be cryptographically secure meaning it is *very hard*
to reconstruct the original IP addresses.

Features:
  * replace all IPs with `0.0.0.0`
  * hash IPs, keeping them distinguishable
  * use a secret salt with hash to hinder reconstruction of the original
    IPs (use `/dev/null` if you want unsalted hashes)
  * optional: re-read the secret if it changed (useful for long-running
    log pipes where the salt is rotated regularly)
  * optional: use PGP words instead of octet notation

Usage
=====

```console
$ python hideip.py -h
usage: hideip.py [-h] [-i INFILE] [-s SECRET] [-o OUTFILE] [-w] [-k]

This module can be used to obfuscate or simply hide ip addresses, e.g. in
server access log files. With a regularly rotated secret, the IPs remain
readable, you can monitor and backtrace the requests of a single IP (for
security auditing, ...) but the actual user IP remains hidden.

optional arguments:
  -h, --help            show this help message and exit
  -i INFILE, --infile INFILE
                        input, read line by line, default: stdin
  -s SECRET, --secret SECRET
                        secret file for rotating IPs (should contain more than
                        64 byte)
  -o OUTFILE, --outfile OUTFILE
                        output, appended to, default: stdout
  -w, --words           replace bytes by words, default: False
  -k, --keep-reading    keep reading the secret file, default: False
```

Test
====

```console
$ python -m doctest hideip.py
```

License
=======

Licensed under GNU GPLv3, see [LICENSE](LICENSE).

Credits
=======

The PGP wordlist is taken from [andreineculau](https://github.com/andreineculau/pgp-word-list) (license: [Unlicense](http://unlicense.org))

