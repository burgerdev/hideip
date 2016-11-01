#!/usr/bin/env python3
# coding: UTF-8
# author: Markus Döring
# license: GPLv3

from unittest import TestCase

from hideip import *


class TestHideIP(TestCase):
    def setUp(self):
        # create temporary file with non-ascii secret
        pass

    def tearDown(self):
        # delete temp file
        pass

    def test_interleave(self):
        self.assertEqual(list(interleave(range(1, 5))),
                         [1, 2, 3, 4])
        self.assertEqual(list(interleave(range(4), range(5,8))),
                         [0, 5, 1, 6, 2, 7, 3])
        self.assertEqual(list(interleave(range(500), range(5,8))),
                         [0, 5, 1, 6, 2, 7, 3])
        self.assertEqual(list(interleave([1, 2], [3, 4], [5, 6])),
                         [1, 3, 5, 2, 4, 6])

    def test_ip2words(self):
        self.assertEqual(ip2words('1.2.3.4'), 'absurd.aftermath.acme.alkali')
        self.assertEqual(ip2words('255.254.255.254'),
                         'Zulu.yesteryear.Zulu.yesteryear')

    def test_rotateip(self):
        self.assertEqual(rotateip('127.0.0.1'), '0.0.0.0')

        hashed = rotateip('127.0.0.1', salt=b"salt")
        self.assertEqual(hashed, '251.135.153.189')

        x = rotateip("127.0.0.1", salt=b"secret")
        y = rotateip("127.0.0.1", salt=b"secret2")
        self.assertNotEqual(x, y)

    def test_replaceip(self):
        test = 'bla 127.0.0.1 blub 255.255.255.255 test'
        self.assertEqual(replaceip(test, words=False),
                         'bla 0.0.0.0 blub 0.0.0.0 test')

        test = 'bla 127.0.0.1 blub '
        salt = b'salt'
        hashed = replaceip(test, salt=salt, words=False)
        self.assertEqual(hashed, 'bla 251.135.153.189 blub ')

        hashed = replaceip(test, salt=salt)
        self.assertEqual(hashed, 'bla watchword.liberty.prowler.quantity blub ')

        u = '192.168.0.1 καὶ 10.10.10.10 δὲν θὰ βρῶ πιὰ στὸ χρυσαφὶ ξέφωτο'
        expected = '0.0.0.0 καὶ 0.0.0.0 δὲν θὰ βρῶ πιὰ στὸ χρυσαφὶ ξέφωτο'
        hashed = replaceip(u, words=False)
        self.assertEqual(hashed, expected)

    def test_parse_time(self):
        self.assertEqual(parse_time('12s'), 12)
        self.assertEqual(parse_time('13m'), 13*60)
        self.assertEqual(parse_time('42h'), 42*60**2)
        self.assertEqual(parse_time('11d'), 11*24*60**2)
