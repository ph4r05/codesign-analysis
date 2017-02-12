#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import argparse
import logging
import coloredlogs
from builtins import int

logger = logging.getLogger(__name__)
coloredlogs.install(level=logging.INFO)


def main():
    args_src = sys.argv
    parser = argparse.ArgumentParser(description='Recodes CSV files to hex & correct format - from puttygen')
    parser.add_argument('--old', dest='old', default=False, action='store_const', const=True,
                        help='Old format n;e;d;p;q')
    parser.add_argument('--idx', dest='idx', default=0, type=int,
                        help='Index to start with')
    parser.add_argument('--no-header', dest='no_header', default=False, action='store_const', const=True,
                        help='No CSV header')
    parser.add_argument('files', nargs=argparse.ZERO_OR_MORE, default=[],
                        help='Files to process')

    args = parser.parse_args(args=args_src[1:])

    if not args.no_header:
        print('id;n;e;p;q;d;t')

    for file_name in args.files:
        with open(file_name, 'r') as hnd:
            for idx, line in enumerate(hnd):
                line = line.strip()
                parts = line.split(';')
                n, e, d, p, q = parts

                # id;n;e;p;q;d;t
                print('%d;%x;%x;%x;%x;%x;0' % (idx + args.idx, int(n), int(e), int(p), int(q), int(d)))


# Launcher
if __name__ == "__main__":
    main()


