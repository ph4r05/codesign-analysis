#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Parses google play android app ranking to the JSON
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


class GPlayParser(object):
    """
    Process google play report
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
        for idx, row in enumerate(tree.xpath('//div[@class="id-card-list card-list two-cards"]/div')):
            details = row.xpath('div/div[@class="details"]')[0]
            atitle = details.xpath('a[@class="title"]')[0]
            asubtitle = details.xpath('div/a[@class="subtitle"]')[0]

            link = atitle.attrib['href']
            title_base = atitle.xpath('text()')[0].strip().split('.', 1)
            rank, title = int(title_base[0]), unicode(title_base[1].strip())
            package = link[link.find('?id=')+4:]
            vendor = asubtitle.attrib['title']
            vendor_link = asubtitle.attrib['href']
            vendor_id = vendor_link[vendor_link.find('?id=')+4:]

            apk = OrderedDict()
            apk['name'] = title
            apk['package'] = package
            apk['vendor'] = vendor
            apk['vendor_id'] = vendor_id
            apk['vendor_link'] = vendor_link
            apk['moreinfo'] = link
            apk['rank'] = rank
            apks.append(apk)

        return apks


def main():
    parser = argparse.ArgumentParser(description='Parses google play Android apps ranking to the JSON')
    parser.add_argument('-f', dest='file', default=None, help='google play ranking file - html')

    args = parser.parse_args()
    rank_file = args.file
    if rank_file is None or not os.path.exists(rank_file):
        print('Ranking file not found')
        parser.print_usage()
        sys.exit(1)

    parser = GPlayParser(rank_file)
    apks = parser.process()
    js = json.dumps({'type': 'googleplay', 'apks': apks}, indent=2)
    print js


# Launcher
if __name__ == "__main__":
    main()



