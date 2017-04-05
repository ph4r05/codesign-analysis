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
    Processing censys 
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

    parser.add_argument('file', nargs=argparse.ZERO_OR_MORE, default=[],
                        help='censys link file')

    args = parser.parse_args()
    if len(args.file) == 0:
        return

    bigdb = {}
    counter = 0
    testrng = range(11, 93)

    with gzip.open(args.file[0], 'rb') as fh:
        for idx, line in enumerate(fh):
            try:
                fprint, cert = line.split(',', 2)
                cert = cert.strip()

                certbin = base64.b64decode(cert)
                bigdb[fprint] = certbin
                counter += 1

                if counter % 10000 == 0:
                    logger.debug(' .. progress %s, fprint %s, memory: %s MB'
                                 % (counter, fprint, utils.get_mem_usage() / 1024.0))

            except Exception as e:
                logger.error('Error in processing %s' % e)
                logger.debug(traceback.format_exc())

    logger.info('Uff... big DB loaded, num entries: %s' % len(bigdb))
    jsdb = None
    with open(args.json, 'r') as fh:
        jsdb = json.load(fh)

    jsdb_ids = {x['id']: x for x in jsdb['data']}
    for test_idx in testrng:
        files = jsdb_ids[test_idx]['files']
        filerec = files[list(files.keys())[0]]
        fname = filerec['name']
        flink = filerec['href']

        # 20131104/20131104_hosts.gz
        fname_2 = fname.split('/')
        if len(fname_2) == 2:
            fname_2 = fname_2[1]
        else:
            fname_2 = fname_2[0]

        dateparts = fname_2.split('_')
        datepart = dateparts[0]

        certfile = os.path.join(args.datadir, '%s_certs.gz' % datepart)
        logger.info('Processing test idx %s, file %s, newfile: %s' % (test_idx, fname, certfile))

        not_found = 0
        fprints_set = set()

        iobj = input_obj.ReconnectingLinkInputObject(flink, files)
        with iobj:
            fh = gzipinputstream.GzipInputStream(fileobj=iobj)
            for rec_idx, rec in enumerate(fh):
                try:
                    linerec = rec.strip().split(',')
                    ip = linerec[0]
                    fprints = linerec[1:]
                    for fprint in fprints:
                        fprints_set.add(fprint)

                    if rec_idx % 10000 == 0:
                        logger.debug(' .. progress %s, ip %s, mem: %s MB'
                                     % (rec_idx, ip, utils.get_mem_usage() / 1024.0))

                except Exception as e:
                    logger.error('Exception in processing rec %s: %s' % (rec_idx, e))
                    logger.debug(rec)
                    logger.debug(traceback.format_exc())

        logger.info('File processed, fprint db size: %d' % len(fprints_set))
        with gzip.open(certfile, 'wb') as outfh:
            for rec_idx, fprint in enumerate(fprints_set):

                if rec_idx % 1000 == 0:
                    outfh.flush()

                if rec_idx % 10000 == 0:
                    logger.debug(' .. progress %s, mem: %s MB'
                                 % (rec_idx, utils.get_mem_usage() / 1024.0))

                if fprint in bigdb:
                    outfh.write('%s,%s\n' % (fprint, base64.b64encode(bigdb[fprint])))

                else:
                    not_found += 1

        logger.info('Finished with idx %s, file %s, newfile: %s, not found: %s'
                    % (test_idx, fname, certfile, not_found))


if __name__ == '__main__':
    main()




