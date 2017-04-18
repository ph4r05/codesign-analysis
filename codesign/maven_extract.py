#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Extracting maven keys identified by key IDs from the json file using big PGP dump 
"""

import re
import os
import json
import argparse
import logging
import coloredlogs
import traceback
import datetime
import utils
import versions as vv
import databaseutils
from collections import OrderedDict

from database import MavenArtifact, MavenSignature
from database import Base as DB_Base

logger = logging.getLogger(__name__)
coloredlogs.install(level=logging.INFO)


class MavenKeyExtract(object):
    """
    Produces simple json array of unique key ids.

    For more advanced setup you may export local snapshot of the DB to the sqlite and compute with the whole
    database on the cluster. https://github.com/dumblob/mysql2sqlite
    """

    def __init__(self):
        self.args = None
        self.fmagic = None

    def work(self):
        """
        Entry point after argument processing.
        :return: 
        """
        if self.args.sec:
            import sec
            self.fmagic = sec.Fprinter()

        logger.info('Generating keyset')

        keyset = set()
        with open(self.args.keys) as fh:
            keylist = json.load(fh)
            for key in keylist:
                keyset.add(int(key, 16))

        logger.info('Key list size: %s, key set size: %s' % (len(keylist), len(keyset)))

        keyset_found = set()
        no_key_id = 0
        keys_res = OrderedDict()
        with open(self.args.json) as fh:
            for idx, line in enumerate(fh):
                try:
                    rec = json.loads(line)
                    if 'key_id' not in rec:
                        no_key_id += 1
                        continue

                    key_id = rec['key_id']
                    key_id_int = int(key_id, 16)
                    if key_id_int not in keyset:
                        continue

                    keyset_found.add(key_id_int)
                    keys_res[key_id_int] = rec
                    logger.info('Key found, db size: %s, mem: %s MB ' % (len(keys_res), utils.get_mem_mb()))
                    print(json.dumps(rec))

                except Exception as e:
                    logger.error('Exception when processing line %s: %s' % (idx, e))
                    logger.debug(traceback.format_exc())

        json_res_file = os.path.join(self.args.data_dir, 'mvn_keys_dump.json')
        with open(json_res_file, 'w') as fw:
            json.dump(keys_res, fw)

        json_missing_file = os.path.join(self.args.data_dir, 'mvn_keys_missing.json')
        with open(json_missing_file, 'w') as fw:
            json.dump(sorted(list(keyset - keyset_found)), fw)

        logger.info('No key id records found: %s' % no_key_id)
        logger.info('No key id records missing: %s' % len(keyset - keyset_found))

    def check_mod(self, rec):
        """
        Checks domain for iont
        :param mod16: 
        :param domain: 
        :param js: 
        :return: 
        """
        if not self.args.sec:
            return

        if 'n' not in rec:
            return

        mod16 = rec['n']
        x = self.fmagic.magic16([mod16])

        if len(x) > 0:
            logger.error('-------------------------------- Keyid: %s' % rec['key_id'])

    def main(self):
        """
        Main entry point
        :return: 
        """
        parser = argparse.ArgumentParser(description='Maven data crawler')

        parser.add_argument('--data', dest='data_dir', default='.',
                            help='Data directory output')

        parser.add_argument('--debug', dest='debug', default=False, action='store_const', const=True,
                            help='Debugging logging')

        parser.add_argument('--sec', dest='sec', default=False, action='store_const', const=True,
                            help='sec')

        parser.add_argument('--keys', dest='keys', default=None,
                            help='JSON array with key IDs')

        parser.add_argument('--json', dest='json', default=None,
                            help='Big json file from pgp dump')

        self.args = parser.parse_args()

        if self.args.debug:
            coloredlogs.install(level=logging.DEBUG)

        self.work()


def main():
    app = MavenKeyExtract()
    app.main()


if __name__ == '__main__':
    main()

