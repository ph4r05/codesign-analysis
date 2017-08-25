#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Parses appannie.com android app ranking to the JSON
"""

import requests
import logging
import coloredlogs
import traceback
import json
import argparse
import sys
import os
import inspect
import re
import math
import hashlib
from lxml import html
from collections import OrderedDict
import binascii

currentdir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
parentdir = os.path.dirname(currentdir)
sys.path.insert(0, parentdir)

try:
    from codesign import utils
except:
    import utils


logger = logging.getLogger(__name__)
coloredlogs.install(level=logging.INFO)


class AppAnnieParser(object):
    """
    Process appannie.com report
    """

    def __init__(self, file_name):
        self.file_name = file_name

    def process(self):
        data = None
        with open(self.file_name, 'r') as fh:
            data = fh.read()

        try:
            tree = html.fromstring(data)
        except Exception as e:
            traceback.print_exc()
            logger.error('Exception in parsing %s' % e)
            return []

        apks = []
        col_type = ['free', 'paid', 'grossing', 'new_free', 'new_paid']

        for idx, row in enumerate(tree.xpath('//div[@class="dashboard-table fixed-columns-table-container"]/'
                                             'div/table/tbody[@data-ref="main"]/tr[@class="main-row table-row"]')):

            row_id = row.xpath('td/span/text()')[0].strip()
            apcols = row.xpath('td[@class="app-with-publisher-rank-iap tbl-col-app-with-publisher-rank-iap"]')

            for col_idx, apcol in enumerate(apcols):
                apk = OrderedDict()

                vals = apcol.xpath('div/div/div[@class="asset-name"]/a/span/text()')
                apk['name'] = vals[0]
                apk['vendor'] = vals[1] if len(vals) > 1 else None

                link = apcol.xpath('div/div/a')[0].attrib['href']
                rdet = link.rfind('/details/')
                apk['moreinfo'] = link
                apk['apptype'] = col_type[col_idx]
                apk['rank'] = int(row_id)

                package = None
                if rdet > 0:
                    package = link[:rdet]
                    package = package[package.rfind('/')+1:]
                apk['package'] = package
                apks.append(apk)

        return apks


def main():
    parser = argparse.ArgumentParser(description='Parses appannie.com Android apps ranking to the JSON')
    parser.add_argument('-f', dest='file', default=None, help='Appannie.com ranking file')

    args = parser.parse_args()
    rank_file = args.file
    if rank_file is None or not os.path.exists(rank_file):
        print('Ranking file not found')
        parser.print_usage()
        sys.exit(1)

    parser = AppAnnieParser(rank_file)
    apks = parser.process()
    js = json.dumps({'type': 'appannie', 'apks': apks}, indent=2, cls=utils.AutoJSONEncoder)
    print(js)


# Launcher
if __name__ == "__main__":
    main()



