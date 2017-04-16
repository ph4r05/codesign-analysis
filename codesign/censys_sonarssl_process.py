#!/usr/bin/env python
# -*- coding: utf-8 -*-
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

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
import collections
import base64
import utils
import coloredlogs
import time
import input_obj
import gzip
import gzipinputstream
from datetime import datetime

logger = logging.getLogger(__name__)
coloredlogs.install(level=logging.DEBUG)


def main():
    """
    Processing censys datasets
    Stored sorted fingerprints, scanning big database of fprints, producing new certificates

    https://scans.io/study/sonar.ssl
    :return:
    """
    parser = argparse.ArgumentParser(description='Processes Censys links from the page, generates json')

    parser.add_argument('--url', dest='url', nargs=argparse.ZERO_OR_MORE, default=[],
                        help='censys links')

    parser.add_argument('--json', dest='json', default=None,
                        help='sonar links json')

    parser.add_argument('--datadir', dest='datadir', default='.',
                        help='datadir')

    args = parser.parse_args()
    testrng = range(10, 93)

    jsdb = None
    with open(args.json, 'r') as fh:
        jsdb = json.load(fh)

    jsdb_ids = {x['id']: x for x in jsdb['data']}
    for test_idx in testrng:
        files = jsdb_ids[test_idx]['files']
        filerec = None
        for tmprec in files:
            if '_hosts.gz' in tmprec:
                filerec = files[tmprec]
                break

        fname = filerec['name']

        # 20131104/20131104_hosts.gz
        fname_2 = fname.split('/')
        if len(fname_2) == 2:
            fname_2 = fname_2[1]
        else:
            fname_2 = fname_2[0]

        dateparts = fname_2.split('_')
        datepart = dateparts[0]

        certfile = os.path.join(args.datadir, '%s_certs.gz' % datepart)
        hostfile = os.path.join(args.datadir, '%s_hosts.gz' % datepart)
        jsonfile = os.path.join(args.datadir, '%s_certs.json' % datepart)
        jsonufile = os.path.join(args.datadir, '%s_certs.uniq.json' % datepart)

        if not os.path.exists(certfile):
            logger.error('Cert file does not exist %s' % certfile)
            continue

        if not os.path.exists(hostfile):
            logger.error('Host file does not exist %s' % certfile)
            continue

        # Load host file, ip->fprint associations.
        fprints_db = collections.defaultdict(list)
        with gzip.open(hostfile) as cf:
            for line in cf:
                linerec = line.strip().split(',')
                ip = linerec[0]
                fprints = linerec[1:]
                for fprint in fprints:
                    lst = fprints_db[fprint]
                    lst.add(ip)

        logger.info('Processed host file, db size: %s' % len(fprints_db))

        # Process
        js_db = []
        with gzip.open(certfile) as cf:
            for line in cf:
                try:
                    js = collections.OrderedDict()
                    linerec = line.strip().split(',')
                    fprint = linerec[0]
                    cert_b64 = linerec[1]
                    cert_bin = base64.b64decode(cert_b64, True)

                    cert = utils.load_x509_der(cert_bin)
                    pub = cert.public_key()
                    if isinstance(pub, RSAPublicKey):
                        not_before = cert.not_valid_before
                        cname = utils.try_get_cname(cert)

                        js['source'] = [cname, not_before.strftime('%Y-%m-%d')]
                        js['e'] = '%x' % pub.public_numbers().e
                        js['n'] = '%x' % pub.public_numbers().n
                        js['nnum'] = pub.public_numbers().n
                        js['info'] = {}
                        if fprint in fprints_db:
                            js['info']['ip'] = fprints_db[fprint]

                        js_db.append(js)

                except Exception as e:
                    logger.error('Exception in rec processing: %s' % e)

        logger.info('Processed certificate file, size: %d' % len(js_db))

        # Sort
        js_db.sort(key=lambda x: x['nnum'])
        with open(jsonfile, 'w') as fh:
            for rec in js_db:
                del rec['nnum']
                fh.write(json.dumps(rec) + '\n')

        logger.info('JSON file produced')

        # Duplicate removal
        # TODO: implement




        pass


if __name__ == '__main__':
    main()




