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


class Link(object):
    """
    Represents one performed test and its result.
    """
    def __init__(self, file_name=None, file_code=None, file_href=None, file_size=None, file_type=None, file_hash=None):
        self.file_name = file_name
        self.file_code = file_code
        self.file_href = file_href
        self.file_size = file_size
        self.file_type = file_type
        self.file_hash = file_hash

    def to_json(self):
        js = collections.OrderedDict()
        js['name'] = self.file_name
        js['code'] = self.file_code
        js['href'] = self.file_href
        js['size'] = self.file_size
        js['type'] = self.file_type
        js['hash'] = self.file_hash
        return js


def main():
    """
    Processing censys link page to the json
    :return:
    """
    parser = argparse.ArgumentParser(description='Processes Censys links from the page, generates json')

    parser.add_argument('file', nargs=argparse.ZERO_OR_MORE, default=[],
                        help='censys link file')

    args = parser.parse_args()

    # Process the input
    if len(args.file) == 0:
        print('Error; no input given')
        sys.exit(1)

    dataset_idx = 0
    datasets = []

    for file_name in args.file:
        logger.info('Processing %s' % file_name)

        with open(file_name, 'r') as fh:
            data = fh.read()
            tree = html.fromstring(data)
            tables = tree.xpath('//table')

            if len(tables) == 0:
                logger.error('Parsing problems, no tables given')
                continue

            for tbl_idx, table in enumerate(tables):
                rows = table[0]
                rows_cnt = len(rows)
                if rows_cnt < 2:
                    logger.warning('Table %d has not enough rows: %d' % (tbl_idx, rows_cnt))
                    continue

                prev_h2 = table.getprevious()
                header = prev_h2.text_content().strip()

                dataset = collections.OrderedDict()
                dataset['id'] = dataset_idx
                dataset['date'] = header
                dataset['date_utc'] = utils.unix_time(datetime.strptime(header, '%Y-%m-%d %H:%M:%S'))
                dataset['files'] = {}
                for row_idx, row in enumerate(rows):
                    if row_idx == 0 or row[0].tag != 'td':
                        continue

                    file_href = row[0][0].attrib['href'].strip()
                    file_code = row[0][0].attrib['download'].strip()
                    file_name = row[0][0].text_content().strip()

                    file_type = row[1].text_content().strip()
                    file_size = row[2].text_content().strip()
                    file_hash = row[3].text_content().strip()
                    # logger.info('File %d %s %s %s %s %s %s' % (row_idx, file_href, file_code, file_name, file_type, file_size, file_hash))

                    link = Link(file_name, file_code, file_href, file_size, file_type, file_hash)
                    dataset['files'][file_name] = link.to_json()

                datasets.append(dataset)
                dataset_idx += 1

    js = collections.OrderedDict()
    js['generated'] = time.time()
    js['data'] = datasets
    print(json.dumps(js, indent=2))


if __name__ == '__main__':
    main()




