#!/usr/bin/env python
# coding: UTF-8
# author: Markus Döring
# license: GPLv3

import json

filename = "pgp-wordlist.json"

with open(filename) as f:
    wordlist = json.load(f)
