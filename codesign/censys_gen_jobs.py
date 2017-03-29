#!/usr/bin/env python
# -*- coding: utf-8 -*-

__author__ = 'dusanklinec'

from past.builtins import cmp
import argparse
import json
import os
import sys
import collections
import itertools
import traceback
import logging
import math
import utils
import coloredlogs
import time
from lxml import html
from datetime import datetime


logger = logging.getLogger(__name__)
coloredlogs.install(level=logging.DEBUG)


def main():
    """
    Generate censys jobs
    https://censys.io/data/443-https-tls-alexa_top1mil/historical
    https://censys.io/data/443-https-tls-full_ipv4/historical
    :return:
    """
    parser = argparse.ArgumentParser(description='Generates Censys jobs')

    parser.add_argument('--home', dest='home',
                        help='homedir')

    parser.add_argument('--data', dest='data',
                        help='data dir')

    parser.add_argument('--wrapper', dest='wrapper',
                        help='python script wrapper')

    parser.add_argument('file', nargs=argparse.ZERO_OR_MORE, default=[],
                        help='censys link file')

    args = parser.parse_args()

    # Process the input
    if len(args.file) == 0:
        print('Error; no input given')
        sys.exit(1)

    dataset_idx = 10
    datasets = []

    for file_name in args.file:
        logger.info('Processing %s' % file_name)

        code = 'fullipv4'
        if 'alexa' in file_name:
            code = 'alexa'

        with open(file_name, 'r') as fh:
            js = json.load(fh)
            for dataset in js['data']:
                id = dataset['id']

                job = '#!/bin/bash\n'
                job += 'cd %s\n' % args.home
                job += '%s --debug --link-file %s --link-idx %d --data %s \n' \
                       % (args.wrapper, file_name, id, args.data)

                with open('%s-%05d.sh' % (code, id), 'w') as jh:
                    jh.write(job)


if __name__ == '__main__':
    main()




