#!/usr/bin/env python
# -*- coding: utf-8 -*-

import pkg_resources
import logging
import coloredlogs
import sys
import argparse
import os
import json
import re
import utils
import traceback
import collections
import datetime
import base64
import hashlib
import binascii
import types

from six import u, b, binary_type, PY3

import base64
import time
import gzip

import input_obj
import newline_reader
from trace_logger import Tracelogger


logger = logging.getLogger(__name__)
coloredlogs.install(level=logging.INFO)


def load_set(file, target_set):
    """
    Loads file to the array
    :param file: 
    :return: 
    """
    if file.endswith('gz'):
        fh = gzip.open(file, 'rb')
    else:
        fh = open(file, 'rb')

    with fh:
        for line in fh:
            ip, tail = line.split(',', 1)
            target_set.add(ip.strip())
    return target_set


def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='IP addr diff')

    parser.add_argument('--datadir', dest='datadir', default='.',
                        help='datadir')

    parser.add_argument('files', nargs=argparse.ZERO_OR_MORE, default=[],
                        help='files')

    args = parser.parse_args()

    ip_first = set()
    ip_second = set()

    if len(args.files) <2:
        logger.error('Has to have at least 2 files')
        return

    logger.info('Loading first file...')
    load_set(args.files[0], ip_first)
    logger.info('File loaded, #of ip addresses: %s' % len(ip_first))

    logger.info('Loading second file...')
    load_set(args.files[1], ip_second)
    logger.info('File loaded, #of ip addresses: %s' % len(ip_second))

    path_ab = os.path.join(args.datadir, 'a_min_b.csv')
    path_ba = os.path.join(args.datadir, 'b_min_a.csv')
    path_sym = os.path.join(args.datadir, 'a_sym_b.csv')
    path_int = os.path.join(args.datadir, 'a_intersection_b.csv')
    path_uni = os.path.join(args.datadir, 'a_union_b.csv')

    with open(path_ab, 'w') as fh:
        res_set = sorted(list(ip_first - ip_second))
        for x in res_set:
            fh.write('%s\n' % x)

    with open(path_ba, 'w') as fh:
        res_set = sorted(list(ip_second - ip_first))
        for x in res_set:
            fh.write('%s\n' % x)

    with open(path_sym, 'w') as fh:
        res_set = sorted(list(ip_first ^ ip_second))
        for x in res_set:
            fh.write('%s\n' % x)

    with open(path_int, 'w') as fh:
        res_set = sorted(list(ip_first & ip_second))
        for x in res_set:
            fh.write('%s\n' % x)

    with open(path_uni, 'w') as fh:
        res_set = sorted(list(ip_first | ip_second))
        for x in res_set:
            fh.write('%s\n' % x)


if __name__ == "__main__":
    main()


