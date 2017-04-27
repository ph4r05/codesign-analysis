#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Check PGP keys & subkeys
"""

import re
import os
import json
import argparse
import logging
import coloredlogs
import traceback
import time
import datetime
import utils
import versions as vv
import databaseutils
from collections import OrderedDict
import sec


logger = logging.getLogger(__name__)
coloredlogs.install(level=logging.INFO)


class PGPCheck(object):
    """
    PGP keys checking
    """

    def __init__(self):
        self.args = None
        self.fmagic = None

        self.config = None
        self.config_file = None
        self.dump_file = None

        self.last_report = 0
        self.last_report_idx = 0
        self.last_flush = 0
        self.report_time = 15

        self.found = 0
        self.found_master_key = 0
        self.found_no_master_key = 0
        self.found_sub_key = 0
        self.found_entities = 0
        self.found_entities_keynum = 0
        self.num_master_keys = 0
        self.num_sub_keys = 0

        self.no_key_id = 0
        self.flat_key_ids = set()

    def work(self):
        """
        Entry working point
        :return: 
        """
        logger.info('Starting...')
        dump_file_path = os.path.join(self.args.data_dir, 'inter_keys.json')
        self.dump_file = open(dump_file_path, 'w')

        # process PGP dump, fill in keys DB
        with open(self.args.json) as fh:
            for idx, line in enumerate(fh):
                try:
                    self.process_record(idx, line)

                except Exception as e:
                    logger.error('Exception when processing line %s: %s' % (idx, e))
                    logger.debug(traceback.format_exc())

        self.dump_file.close()

        # fprint keys
        logger.info('Job finished')
        logger.info('Found: %s' % self.found)
        logger.info('Found entities: %s' % self.found_entities)
        logger.info('Found master: %s' % self.found_master_key)
        logger.info('Found no master: %s' % self.found_no_master_key)
        logger.info('Found sub key: %s' % self.found_sub_key)
        logger.info('Found avg num of keys: %s' % float(self.found_entities_keynum) / self.found_entities)
        logger.info('Num master keys: %s' % self.num_master_keys)
        logger.info('Num sub keys: %s' % self.num_sub_keys)

        keys_path = os.path.join(self.args.data_dir, 'inter_keys_ids.json')
        with open(keys_path, 'w') as fw:
            for x in sorted(list(self.flat_key_ids)):
                fw.write(utils.format_pgp_key(x) + '\n')

    def process_record(self, idx, line):
        """
        Processes one record from PGP dump
        :param idx: 
        :param line: 
        :return: 
        """
        rec = json.loads(line)
        master_key_id = int(utils.defvalkey(rec, 'key_id', '0'), 16)
        master_fingerprint = utils.defvalkey(rec, 'fingerprint')

        flat_keys = [rec]
        user_names = []

        # Phase 1 - info extraction
        if 'packets' in rec:
            for packet in rec['packets']:
                if packet['tag_name'] == 'User ID':
                    utils.append_not_none(user_names, utils.defvalkey(packet, 'user_id'))
                elif packet['tag_name'] == 'Public-Subkey':
                    flat_keys.append(packet)

        # Test all keys
        self.test_flat_keys(flat_keys, user_names, master_key_id, master_fingerprint, rec)

        if time.time() - self.last_report > self.report_time:
            per_second = (idx - self.last_report_idx) / float(self.report_time)
            logger.debug(' .. report idx: %s, per second: %2.2f, found: %s, '
                         'num_master: %s, num_sub: %s, ratio: %s, cur key: %016X '
                         % (idx, per_second, self.found, self.num_master_keys, self.num_sub_keys,
                            float(self.num_sub_keys) / self.num_master_keys, master_key_id))

            self.last_report = time.time()
            self.last_report_idx = idx

    def test_flat_keys(self, flat_keys, user_names, master_key_id, master_fingerprint, rec):
        """
        Tests all keys in the array
        :param flat_keys: 
        :return: 
        """
        if flat_keys is None or len(flat_keys) == 0:
            return

        self.num_master_keys += 1
        self.num_sub_keys += len(flat_keys) - 1

        tested = [self.test_key(x) for x in flat_keys]
        if any(tested):
            flat_key_ids = [int(utils.defvalkey(x, 'key_id', '0'), 16) for x in flat_keys]
            keys_hex = [utils.format_pgp_key(x) for x in flat_key_ids]
            det_key_ids = [x for _idx, x in enumerate(flat_key_ids) if tested[_idx]]

            logger.info('------- interesting map: %s for key ids %s' % (tested, keys_hex))

            js = OrderedDict()
            js['detection'] = tested
            js['key_ids'] = keys_hex
            js['names'] = user_names
            js['master_key_id'] = utils.format_pgp_key(master_key_id)
            js['master_key_fprint'] = master_fingerprint
            # js['pgp'] = rec

            self.dump_file.write(json.dumps(js) + '\n')
            self.dump_file.flush()

            self.found_no_master_key += not tested[0]
            self.found_master_key += tested[0]
            self.found_sub_key += sum(tested[1:])
            self.found += sum(tested)
            self.found_entities += 1
            self.found_entities_keynum += len(tested)
            for x in det_key_ids:
                self.flat_key_ids.add(x)

    def test_key(self, rec=None):
        """
        Fingerprint test
        :param rec: 
        :return: 
        """
        if rec is None:
            return False

        n = utils.defvalkey(rec, 'n')
        if n is None:
            return False

        x = self.fmagic.magic16([n])
        if len(x) > 0:
            return True
        return False

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

        parser.add_argument('-c', dest='config', default=None,
                            help='JSON config file')

        parser.add_argument('--data', dest='data_dir', default='.',
                            help='Data directory output')

        parser.add_argument('--debug', dest='debug', default=False, action='store_const', const=True,
                            help='Debugging logging')

        parser.add_argument('--json', dest='json', default=None,
                            help='Big json file from pgp dump')

        self.args = parser.parse_args()
        self.config_file = self.args.config

        self.fmagic = sec.Fprinter()

        if self.args.debug:
            coloredlogs.install(level=logging.DEBUG)

        self.work()


def main():
    app = PGPCheck()
    app.main()


if __name__ == '__main__':
    main()

