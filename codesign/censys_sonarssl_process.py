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
    utils.monkey_patch_asn1_time()

    parser = argparse.ArgumentParser(description='Processes Censys links from the page, generates json')

    parser.add_argument('--url', dest='url', nargs=argparse.ZERO_OR_MORE, default=[],
                        help='censys links')

    parser.add_argument('--json', dest='json', default=None,
                        help='sonar links json')

    parser.add_argument('--datadir', dest='datadir', default='.',
                        help='datadir')

    parser.add_argument('--proc-total', dest='proc_total', default=1, type=int,
                        help='Total number of processes to run')

    parser.add_argument('--proc-cur', dest='proc_cur', default=0, type=int,
                        help='ID of the current process')

    args = parser.parse_args()
    testrng = range(10, 93)

    jsdb = None
    with open(args.json, 'r') as fh:
        jsdb = json.load(fh)

    jsdb_ids = {x['id']: x for x in jsdb['data']}
    for test_idx in testrng:
        if int(test_idx % args.proc_total) != int(args.proc_cur):
            continue

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

        logger.info('Test idx: %d date part: %s, ram: %s MB' % (test_idx, datepart, utils.get_mem_mb()))
        if not os.path.exists(certfile):
            logger.error('Cert file does not exist %s' % certfile)
            continue

        if not os.path.exists(hostfile):
            logger.error('Host file does not exist %s' % certfile)
            continue

        # Load host file, ip->fprint associations.
        logger.info('Building fprint database ram: %s MB' % utils.get_mem_mb())
        fprints_db = collections.defaultdict(list)
        with gzip.open(hostfile) as cf:
            for line in cf:
                linerec = line.strip().split(',')
                ip = linerec[0]
                fprints = linerec[1:]
                for fprint in fprints:
                    lst = fprints_db[fprint]
                    lst.append(ip)

        logger.info('Processed host file, db size: %s, ram: %s MB' % (len(fprints_db), utils.get_mem_mb()))

        # Process
        last_info_time = 0
        last_info_line = 0
        line_ctr = 0
        js_db = []
        with gzip.open(certfile) as cf:
            for line in cf:
                try:
                    line_ctr += 1
                    js = collections.OrderedDict()
                    linerec = line.strip().split(',')
                    fprint = linerec[0]
                    cert_b64 = linerec[1]
                    cert_bin = base64.b64decode(cert_b64)

                    cert = utils.load_x509_der(cert_bin)
                    pub = cert.public_key()
                    if isinstance(pub, RSAPublicKey):
                        not_before = cert.not_valid_before
                        cname = utils.try_get_cname(cert)

                        js['source'] = [cname, not_before.strftime('%Y-%m-%d')]
                        js['e'] = '%x' % pub.public_numbers().e
                        js['n'] = '%x' % pub.public_numbers().n
                        js['nnum'] = pub.public_numbers().n
                        js['info'] = {'ip': []}
                        if fprint in fprints_db:
                            js['info']['ip'] = fprints_db[fprint]

                        js_db.append(js)

                        if line_ctr - last_info_line > 1000 and time.time() - last_info_time > 30:
                            logger.info('Progress, line: %09d, mem: %s MB, db size: %09d, from last: %05d, cname: %s'
                                        % (line_ctr, utils.get_mem_mb(), len(js_db), line_ctr - last_info_line, cname))
                            last_info_time = time.time()
                            last_info_line = line_ctr

                except ValueError as e:
                    logger.error('Exception in rec processing (ValueError): %s, line %09d' % (e, line_ctr))

                except Exception as e:
                    logger.error('Exception in rec processing: %s' % e)
                    logger.debug(traceback.format_exc())

        logger.info('Processed certificate file, size: %d, mem: %s MB' % (len(js_db), utils.get_mem_mb()))

        # Sort
        js_db.sort(key=lambda x: x['nnum'])
        logger.info('Sorted, mem: %s MB' % utils.get_mem_mb())

        with open(jsonfile, 'w') as fh:
            for rec in js_db:
                del rec['nnum']
                fh.write(json.dumps(rec) + '\n')

        logger.info('JSON file produced, mem: %s MB' % utils.get_mem_mb())

        # Duplicate removal
        with open(jsonufile, 'w') as fh:
            for k, g in itertools.groupby(js_db, key=lambda x: x['n']):
                js = g[0]
                js['count'] = len(g)
                ips = []
                for rec in g:
                    ips += rec['info']['ip']
                fh.write(json.dumps(js) + '\n')


if __name__ == '__main__':
    main()




