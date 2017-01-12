#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Crawls apkpure.com for apps chart.
Downloads APKs directly.

Signature of the APK can be verified by:
jarsigner -verify -verbose -certs my_application.apk
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
import hashlib

from cryptography.hazmat.primitives.asymmetric.dsa import DSAPublicKey
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

import utils
from lxml import html
from collections import OrderedDict
from apk_parse.apk import APK
import binascii
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.x509.base import load_pem_x509_certificate
from cryptography.hazmat.primitives import hashes


logger = logging.getLogger(__name__)
coloredlogs.install(level=logging.INFO)


class ApkPureLoader(object):
    """
    Crawling apkpure.com - downloading APKs
    """

    BASE_URL = 'https://apkpure.com'

    def __init__(self, db, dump_dir, attempts=10):
        self.attempts = attempts
        self.total = None
        self.per_page = None
        self.db = db
        self.dump_dir = dump_dir

    def load(self, idx=None):
        """
        Loads page with attempts
        :param idx:
        :return:
        """
        for i in range(0, self.attempts):
            try:
                return self.load_once(idx)
            except Exception as e:
                traceback.print_exc()
                pass
        return None

    def load_once(self, idx=None):
        """
        Loads page once
        :param idx:
        :return:
        """
        apk_rec = self.db['apks'][idx]
        url = self.BASE_URL + apk_rec['download']
        file_name = utils.slugify(apk_rec['package'] + '.apk')
        file_path = os.path.join(self.dump_dir, file_name)

        logger.info('Downloading pkg %s, name: %s, url %s' % (apk_rec['package'], apk_rec['name'], url))
        if not os.path.exists(file_path):
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
            try:
                tree = html.fromstring(data)
            except Exception as e:
                logger.warning('Exception in parsing, finishing with page %s' % idx)
                return

            anchors = tree.xpath('//a[@id="download_link"]')
            if len(anchors) == 0:
                logger.warning('No download link found')
                return

            download_link = anchors[0].attrib['href']
            logger.info('Downloading link: %s' % download_link)

            # Download with removal if exception is thrown
            try:
                sha1 = hashlib.sha1()
                md5 = hashlib.md5()
                r = requests.get(download_link, stream=True)
                with open(file_path, 'wb') as f:
                    for chunk in r.iter_content(chunk_size=4096):
                        if chunk:  # filter out keep-alive new chunks
                            f.write(chunk)
                            sha1.update(chunk)
                            md5.update(chunk)
                    f.flush()

                logger.info('Downloaded to: %s' % file_path)
                apk_rec['size'] = os.path.getsize(file_path)
                apk_rec['sha1'] = sha1.hexdigest()
                apk_rec['md5'] = md5.hexdigest()

            except Exception as e:
                traceback.print_exc()
                logger.error('Exception during download: %s' % e)
                os.remove(file_path)

        # Downloaded - now parse
        try:
            logger.info('Parsing APK')
            apkf = APK(file_path)
            pem = apkf.cert_pem

            x509 = utils.load_x509(pem)
            apk_rec['cert_alg'] = x509.signature_hash_algorithm.name

            pub = x509.public_key()
            if isinstance(pub, RSAPublicKey):
                apk_rec['pubkey_type'] = 'RSA'
                mod = pub.public_numbers().n
                apk_rec['modulus'] = mod
                apk_rec['modulus_hex'] = '%x' % mod
                apk_rec['modulus_size'] = len(bin(mod)) - 2
                apk_rec['cert_e'] = x509.public_key().public_numbers().e
                apk_rec['cert_e_hex'] = '%x' % apk_rec['cert_e']
                print('%x' % mod)

            elif isinstance(pub, DSAPublicKey):
                apk_rec['pubkey_type'] = 'DSA'

            elif isinstance(pub, EllipticCurvePublicKey):
                apk_rec['pubkey_type'] = 'ECC'

            else:
                apk_rec['pubkey_type'] = ''

            utils.extend_with_cert_data(apk_rec, x509, logger)
            apk_rec['pem'] = pem

        except Exception as e:
            traceback.print_exc()
            logger.error('APK parsing failed')


def main():
    parser = argparse.ArgumentParser(description='Downloads APKs from the apkpure')
    parser.add_argument('-d', dest='directory', default='.', help='Directory to dump the downloaded APK files')
    parser.add_argument('-c', dest='config', default=None, help='JSON config file')

    args = parser.parse_args()
    dump_dir = args.directory
    json_path = args.config

    if json_path is None or not os.path.exists(json_path):
        print('JSON file not found')
        parser.print_usage()
        sys.exit(1)

    db = None
    with open(json_path, 'r') as fh:
        db = json.load(fh, object_pairs_hook=OrderedDict)

    t = ApkPureLoader(db, dump_dir)
    for idx in range(0, len(db['apks'])):
        t.load(idx)

        # re-save
        new_json = os.path.join(dump_dir, '_apks_info.json')
        with open(new_json, 'w') as fh:
            fh.write(json.dumps(db, indent=2))
            fh.flush()


# Launcher
if __name__ == "__main__":
    main()


