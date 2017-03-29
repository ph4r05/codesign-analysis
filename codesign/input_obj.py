#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Input objects taken from polynomial verifiers
"""


import hashlib
import logging
import os
import sys
import requests


logger = logging.getLogger(__name__)


class InputObject(object):
    """
    Input stream object.
    Can be a file, stream, or something else
    """
    def __init__(self, *args, **kwargs):
        self.sha256 = hashlib.sha256()
        self.data_read = 0

    def __enter__(self):
        pass

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

    def __repr__(self):
        return 'InputObject()'

    def check(self):
        """
        Checks if stream is readable
        :return:
        """

    def size(self):
        """
        Returns the size of the data
        :return:
        """
        return -1

    def read(self, size):
        """
        Reads size of data
        :param size:
        :return:
        """
        raise NotImplementedError('Not implemented - base class')

    def handle(self):
        """
        Returns file like handle
        :return: 
        """
        raise NotImplementedError('Not implemented - base class')


class FileInputObject(InputObject):
    """
    File input object - reading from the file
    """
    def __init__(self, fname, *args, **kwargs):
        super(FileInputObject, self).__init__(*args, **kwargs)
        self.fname = fname
        self.fh = None

    def __enter__(self):
        super(FileInputObject, self).__enter__()
        self.fh = open(self.fname, 'r')

    def __exit__(self, exc_type, exc_val, exc_tb):
        super(FileInputObject, self).__exit__(exc_type, exc_val, exc_tb)
        try:
            self.fh.close()
        except:
            logger.error('Error when closing file %s descriptor' % self.fname)

    def __repr__(self):
        return 'FileInputObject(file=%r)' % self.fname

    def __str__(self):
        return self.fname

    def check(self):
        if not os.path.exists(self.fname):
            raise ValueError('File %s was not found' % self.fname)

    def size(self):
        return os.path.getsize(self.fname)

    def read(self, size):
        data = self.fh.read(size)
        self.sha256.update(data)
        self.data_read += len(data)
        return data

    def handle(self):
        return self.fh


class LinkInputObject(InputObject):
    """
    Input object using link - remote load
    """
    def __init__(self, url, headers=None, auth=None, *args, **kwargs):
        super(LinkInputObject, self).__init__(*args, **kwargs)
        self.url = url
        self.headers = headers
        self.auth = auth
        self.r = None

    def __enter__(self):
        super(LinkInputObject, self).__enter__()
        self.r = requests.get(self.url, stream=True, allow_redirects=True, headers=self.headers, auth=self.auth)

    def __exit__(self, exc_type, exc_val, exc_tb):
        super(LinkInputObject, self).__exit__(exc_type, exc_val, exc_tb)
        try:
            self.r.close()
        except:
            logger.error('Error when closing url %s descriptor' % self.url)

    def __repr__(self):
        return 'LinkInputObject(file=%r)' % self.url

    def __str__(self):
        return self.url

    def check(self):
        return True

    def size(self):
        return -1

    def read(self, size):
        data = self.r.raw.read(size)
        self.sha256.update(data)
        self.data_read += len(data)
        return data

    def handle(self):
        return self.r.raw


