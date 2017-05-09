#!/usr/bin/env python
# -*- coding: utf-8 -*-

import collections
import time


class RateLimitHit(Exception):
    """
    Rate limit exceeded
    """


class AccessResource(object):
    """
    Represents one access token
    """
    __slots__ = ['idx', 'usr', 'token', '_remaining', 'reset_time', 'last_used', 'used_cnt', 'fail_cnt']

    def __init__(self, usr=None, token=None, remaining=None, reset_time=None, idx=0, *args, **kwargs):
        self.idx = idx
        self.usr = usr
        self.token = token
        self._remaining = remaining
        self.reset_time = reset_time
        self.last_used = idx
        self.used_cnt = 0
        self.fail_cnt = 0

    @property
    def remaining(self):
        """
        If reset time is 5 minutes expired then remaining estimation is not correct.
        In that case we reset the counters so workers try again this credential & reload estimation.
        :return:
        """
        if self._remaining is None or self.reset_time is None:
            return self._remaining

        if self.reset_time + 300 < time.time():
            self._remaining = None

        return self._remaining

    @remaining.setter
    def remaining(self, val):
        self._remaining = val

    def __cmp__(self, other):
        """
        Compare operation for priority queue.
        :param other:
        :return:
        """
        me_rem = self.remaining
        he_rem = other.remaining

        if me_rem is None and he_rem is None:
            return self.last_used - other.last_used
        elif me_rem is None:
            return -1
        elif he_rem is None:
            return 1
        else:
            return he_rem - me_rem

    def to_json(self):
        js = collections.OrderedDict()
        js['usr'] = self.usr
        js['remaining'] = self.remaining
        js['reset_time'] = self.reset_time
        js['last_used'] = self.last_used
        js['used_cnt'] = self.used_cnt
        js['fail_cnt'] = self.fail_cnt
        return js

