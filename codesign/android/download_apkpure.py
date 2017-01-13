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
import inspect
import time
import shutil

from cryptography.hazmat.primitives.asymmetric.dsa import DSAPublicKey
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

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


class ApkPureLoader(object):
    """
    Crawling apkpure.com - downloading APKs
    """

    BASE_URL = 'https://apkpure.com'

    def __init__(self, db, dump_dir, tmp_dir=None, attempts=5):
        self.attempts = attempts
        self.total = None
        self.per_page = None
        self.db = db
        self.dump_dir = dump_dir
        self.tmp_dir = tmp_dir
        self.terminate = False

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
                time.sleep(3.0)
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

        apk_processed = self.is_apk_processed(apk_rec)
        download_again = not apk_processed and not os.path.exists(file_path)

        logger.info('Downloading [%d/%d] pkg %s, apk_processed: %s, download: %s\n\tname: %s, \n\turl %s'
                    % (idx, len(self.db['apks']), apk_rec['package'],
                       apk_processed, download_again, apk_rec['name'], url))

        if not apk_processed and not download_again and ('size' not in apk_rec or apk_rec['size'] is None):
            logger.info('Size none or null, downloading')
            download_again = True

        if not apk_processed and not download_again and ('size' in apk_rec and apk_rec['size'] < 500):
            logger.info('Size to small, downloading')
            download_again = True

        if download_again:
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
            apk_rec['direct_link'] = download_link
            logger.info('Downloading link: %s' % download_link)

            # Download with removal if exception is thrown
            try:
                sha1 = hashlib.sha1()
                md5 = hashlib.md5()
                r = requests.get(download_link, stream=True)
                with open(file_path, 'wb') as f:
                    for chunk in r.iter_content(chunk_size=4096):
                        if chunk:
                            f.write(chunk)
                            sha1.update(chunk)
                            md5.update(chunk)
                    f.flush()

                size = os.path.getsize(file_path)
                if size < 500:
                    raise Exception('File size too small: %s' % size)

                logger.info('Downloaded to: %s' % file_path)
                apk_rec['size'] = size
                apk_rec['sha1'] = sha1.hexdigest()
                apk_rec['md5'] = md5.hexdigest()

            except (KeyboardInterrupt, Exception) as e:
                traceback.print_exc()
                logger.error('Exception during download: %s' % e)
                apk_rec['size'] = None
                apk_rec['sha1'] = None
                apk_rec['md5'] = None
                if isinstance(e, KeyboardInterrupt):
                    self.terminate = True
                try:
                    logger.info('Removing non-finished file: %s' % file_path)
                    os.remove(file_path)
                except:
                    pass

                return

        # Process APK
        self.process_apk(file_path, apk_rec)

    def is_rsa(self, apk_rec):
        return 'pubkey_type' in apk_rec and apk_rec['pubkey_type'] == 'RSA'

    def is_apk_processed(self, apk_rec):
        """
        Returns true if the APK was processed correctly
        :param apk_rec:
        :return:
        """
        if 'pubkey_type' not in apk_rec:
            logger.info('Parse again - key type not found')
            return False

        if 'apk_version_code' not in apk_rec:
            logger.info('Parse again - version missing')
            return False

        if apk_rec['pubkey_type'] is not None and apk_rec['pubkey_type'] in ['DSA', 'ECC']:
            logger.info('DSA/ECC key type, skipping')
            return True

        if 'modulus' not in apk_rec or not isinstance(apk_rec['modulus'], (int, long)) or apk_rec['modulus'] == 0:
            logger.info('Parse again - modulus invalid')
            return False

        if 'modulus_hex' not in apk_rec or len(apk_rec['modulus_hex']) < 10:
            logger.info('Parse again - hex modulus invalid')
            return False

        if 'pubkey_type' not in apk_rec:
            logger.info('Parse again - key type not found')
            return False

        return True

    def process_apk(self, file_path, apk_rec):
        """
        Processing APK - extracting useful information, certificate.
        :param file_path:
        :param apk_rec:
        :return:
        """
        parse_again = False
        if 'pubkey_type' not in apk_rec:
            logger.info('Parse again - key type not found')
            parse_again = True

        elif 'apk_version_code' in apk_rec and apk_rec['pubkey_type'] != 'RSA':
            logger.info('Skipping re-parsing of non-RSA certificates: %s' % apk_rec['pubkey_type'])
            return

        if not self.is_apk_processed(apk_rec):
            parse_again = True

        if not parse_again:
            print(apk_rec['modulus_hex'])
            return

        # Downloaded - now parse
        try:
            logger.info('Parsing APK')

            # Optimized parsing - parse only manifest and certificate, no file type inference.
            # In case of xapks (nested apks), use temp dir to extract it.
            apkf = APK(file_path, process_now=False, process_file_types=False, as_file_name=True, temp_dir=self.tmp_dir)

            # Save some time - do not re-compute MD5 inside apk parsing lib
            if 'md5' in apk_rec:
                apkf.file_md5 = apk_rec['md5']

            apkf.process()
            apk_rec['is_xapk'] = apkf.is_xapk
            apk_rec['sub_apk_size'] = apkf.sub_apk_size

            # Android related info (versions, SDKs)
            utils.extend_with_android_data(apk_rec, apkf, logger)
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
    parser.add_argument('--tmp', dest='tmp_dir', default='/tmp', help='temporary folder for analysis')

    args = parser.parse_args()
    dump_dir = args.directory
    json_path = args.config
    tmp_dir = args.tmp_dir

    if json_path is None or not os.path.exists(json_path):
        print('JSON file not found')
        parser.print_usage()
        sys.exit(1)

    db = None
    with open(json_path, 'r') as fh:
        db = json.load(fh, object_pairs_hook=OrderedDict)

    last_save = 0
    t = ApkPureLoader(db, dump_dir, tmp_dir)
    for idx in range(0, len(db['apks'])):
        t.load(idx)

        # re-save each 5 seconds.
        cur_time = time.time()
        if cur_time - last_save <= 5.0:
            continue

        new_json = os.path.join(dump_dir, '_apks_info.json')
        new_json_tmp = os.path.join(dump_dir, '_apks_info.json.tmp')
        with open(new_json_tmp, 'w') as fh:
            fh.write(json.dumps(db, indent=2))
            fh.flush()
            last_save = cur_time
        shutil.move(new_json_tmp, new_json)

        if t.terminate:
            logger.info('Terminating on loader request')
            break


# Launcher
if __name__ == "__main__":
    main()


