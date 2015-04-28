#!/usr/bin/env python
# coding: UTF-8
# author: Markus Döring
# license: GPLv3

import os
import json

filename = "pgp-wordlist.json"
dirname = os.path.dirname(__file__)
filename = os.path.join(dirname, filename)

with open(filename) as f:
    wordlist = json.load(f)
