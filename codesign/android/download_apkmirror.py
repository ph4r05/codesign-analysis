#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Extracts direct download link & metadata
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
import urllib
import math
import hashlib
import inspect
import time
import shutil

from lxml import html
from collections import OrderedDict
from apk_parse.apk import APK

currentdir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
parentdir = os.path.dirname(currentdir)
sys.path.insert(0, parentdir)

try:
    from codesign import utils
except:
    import utils


logger = logging.getLogger(__name__)
coloredlogs.install(level=logging.INFO)


class ApkMirrorLoader(object):
    """
    Downloading apkmirror.com
    """

    BASE_URL = 'https://www.apkmirror.com'

    def __init__(self, attempts=5):
        self.attempts = attempts
        self.total = None
        self.per_page = None
        self.terminate = False

    def load(self, package):
        """
        Loads page with attempts
        :param package:
        :return:
        """
        for i in range(0, self.attempts):
            try:
                return self.load_once(package)
            except Exception as e:
                traceback.print_exc()
                time.sleep(3.0)
        return None

    def load_page(self, url):
        """
        Loads URL to tree
        :param url:
        :return:
        """
        res = requests.get(url, timeout=20)
        if math.floor(res.status_code / 100) != 2.0:
            res.raise_for_status()
        data = res.content
        if data is None:
            raise Exception('Empty response')

        tree = html.fromstring(data)
        return tree

    def load_once(self, package):
        """
        Loads page once
        :param package:
        :return:
        """
        apk_rec = OrderedDict()

        search_url = self.BASE_URL + ('/?s=%s&post_type=app_release&searchtype=apk' % package)
        apk_rec['url_search'] = search_url

        # Search according to package name
        logger.info('Downloading search %s, link: %s' % (package, search_url))
        tree = self.load_page(search_url)

        # Search result - container element
        elist = tree.xpath('//div[@id="content"]/div[@class="listWidget"]')[0]

        # App row
        eapp = elist.xpath('div[@class="appRow"]')
        einfo = elist.xpath('div[@class="infoSlide"]')

        if len(eapp) == 0:
            logger.warning('No results')
            return apk_rec

        eapp1 = eapp[0]
        ahref = eapp1.xpath('div/div/div/h5/a')[0]
        link = ahref.attrib['href']
        title = ahref.xpath('text()')
        print(title, link)

        # Download details page
        detail_url = self.BASE_URL + link
        apk_rec['url_detail'] = detail_url
        logger.info('Downloading detail info: %s' % detail_url)
        tree = self.load_page(detail_url)

        # Sometimes there are more APKs matching
        ahref = tree.xpath('//div[@class="table-cell rowheight addseparator expand pad dowrap"]/a')
        if len(ahref) > 0:
            ahref = ahref[0]
            link = ahref.attrib['href']
            title = ahref.xpath('text()')
            logger.info('Title: %s, link: %s' % (title, link))

            # Download particular APK page
            detail_url = self.BASE_URL + link
            apk_rec['url_detail2'] = detail_url
            logger.info('Downloading APK detail info: %s' % detail_url)
            tree = self.load_page(detail_url)

        ahref = tree.xpath('//a[@class="btn btn-flat downloadButton"]')[0]
        link = ahref.attrib['href']
        logger.info('Download link: %s' % link)
        # TODO: fetch more info about the APK

        # Fetch page with direct link
        download_url = self.BASE_URL + link
        apk_rec['url_download'] = download_url
        logger.info('Downloading APK download info: %s' % download_url)
        tree = self.load_page(download_url)

        ahref = tree.xpath('//div[@class="noPadding col-md-6 col-sm-6 col-xs-12"]/p/a')[0]
        link = ahref.attrib['href']
        logger.info('Direct link: %s' % link)


def main():
    parser = argparse.ArgumentParser(description='Downloads APKs from the apkpure')
    parser.add_argument('-d', dest='directory', default='.', help='Directory to dump the downloaded APK files')
    parser.add_argument('-c', dest='config', default=None, help='JSON config file')
    parser.add_argument('--tmp', dest='tmp_dir', default='/tmp', help='temporary folder for analysis')
    parser.add_argument('-p', dest='package', default=None, help='Single package to download')

    args = parser.parse_args()
    dump_dir = args.directory
    json_path = args.config
    tmp_dir = args.tmp_dir

    # TODO: finish
    pkg = args.package
    l = ApkMirrorLoader()
    apk = l.load(pkg)
    print(json.dumps(apk, indent=2, cls=utils.AutoJSONEncoder))


# Launcher
if __name__ == "__main__":
    main()


