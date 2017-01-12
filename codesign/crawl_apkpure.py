#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Crawls apkpure.com for apps chart.
"""

import requests
import logging
import coloredlogs
import traceback
import json
import argparse
import sys
import os
import re
import math
from lxml import html
from collections import OrderedDict


logger = logging.getLogger(__name__)
coloredlogs.install(level=logging.INFO)


class ApkPureLoader(object):
    """
    Crawling apkpure.com
    """

    BASE_URL = 'https://apkpure.com'

    def __init__(self, attempts=10):
        self.attempts = attempts
        self.total = None
        self.per_page = None

    def load(self, idx=None, mode='app', offset=0):
        """
        Loads page with attempts
        :param idx:
        :param mode:
        :return:
        """
        for i in range(0, self.attempts):
            try:
                return self.load_once(idx, mode, offset)
            except Exception as e:
                traceback.print_exc()
                pass
        return None

    def load_once(self, idx=None, mode=None, offset=0):
        """
        Loads page once
        :param idx:
        :return:
        """
        url = self.BASE_URL

        if idx is None:
            idx = 1

        url += '/%s?page=%d&ajax=1' % (mode, idx)

        res = requests.get(url, timeout=20)
        if math.floor(res.status_code / 100) != 2.0:
            res.raise_for_status()

        data = res.content
        if data is None:
            return []

        data = data.strip()
        if len(data) == 0:
            return []

        tree = None
        apks = []

        try:
            tree = html.fromstring(data)
        except Exception as e:
            logger.info('Exception in parsing, finishing with page %s' % idx)
            return []

        for idx, li in enumerate(tree.cssselect('li')):
            anchors = li.xpath('div/a')
            ahref = anchors[0].attrib['href']
            title = anchors[0].attrib['title']
            package = ahref[ahref.rfind('/')+1:]
            download_link = anchors[-1].attrib['href']

            js = OrderedDict()
            js['name'] = title
            js['package'] = package
            js['download'] = download_link
            js['moreinfo'] = ahref
            js['apptype'] = mode
            js['rank'] = offset + idx
            apks.append(js)

            print('%d: Title: %s, package: %s, href: %s, download link: %s'
                  % (idx, title, package, ahref, download_link))

        return apks


def dump_apps(mode, state_file, apks):
    t = ApkPureLoader()
    page = 1

    while True:
        part_apks = t.load(page, mode=mode, offset=(page - 1) * 20)
        if part_apks is None:
            print('Warning! Empty apk list on page %s' % page)
            sys.exit(1)

        if len(part_apks) == 0:
            logger.info('Mode %s finished' % mode)
            return

        apks += part_apks
        with open(state_file, 'w') as fh:
            fh.write(json.dumps({'apks': apks}, indent=2))

        print('Page %s loaded' % page)
        page = page + 1 if page is not None else 1


def main():
    parser = argparse.ArgumentParser(description='Crawls apkpure.com for APKs')
    parser.add_argument('-d', dest='directory', default='.',
                        help='Directory to dump the files')

    args = parser.parse_args()
    dump_dir = args.directory
    state_file = os.path.join(dump_dir, 'apps.json')

    apks = []
    dump_apps('app', state_file, apks)
    dump_apps('game', state_file, apks)


# Launcher
if __name__ == "__main__":
    main()


