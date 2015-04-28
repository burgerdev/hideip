#!/usr/bin/env python
# Author: Markus Doering

import json

filename = "pgp-wordlist.json"

with open(filename) as f:
    wordlist = json.load(f)
