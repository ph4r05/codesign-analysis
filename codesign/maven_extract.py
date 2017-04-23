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
import time
import datetime
import utils
import versions as vv
import databaseutils
from collections import OrderedDict

import sqlalchemy
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session
from database import MavenArtifact, MavenSignature, PGPKey
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

        self.config = None
        self.config_file = None

        self.db_config = None
        self.engine = None
        self.session = None

        self.last_report = 0
        self.found = 0
        self.keys_added = 0
        self.keyset = set()
        self.keyset_found = set()
        self.no_key_id = 0
        self.already_loaded = set()

    def init_config(self):
        """
        Loads config & state files
        :return:
        """
        with open(self.config_file, 'r') as fh:
            self.config = json.load(fh, object_pairs_hook=OrderedDict)
            logger.info('Config loaded: %s' % os.path.abspath(self.config_file))

    def init_db(self):
        """
        Initializes database engine & session.
        Has to be done on main thread.
        :return:
        """
        # sqlite variant:
        # dbname = 'sqlite:///%s' % self.sqlite_file

        self.db_config = databaseutils.process_db_config(self.config['db'])
        self.engine = create_engine(self.db_config.constr, pool_recycle=3600)
        self.session = scoped_session(sessionmaker(bind=self.engine))

        # Make sure tables are created
        DB_Base.metadata.create_all(self.engine)

    def work_db(self):
        """
        Work with DB
        :return: 
        """
        logger.info('Starting...')
        self.init_config()
        self.init_db()
        logger.info('Database initialized')

        sess = self.session()

        # Select all existing key ids
        existing_keys = sess.query(PGPKey.key_id).all()
        for rec in existing_keys:
            self.already_loaded.add(int(rec.key_id, 16))
        logger.info('Already loaded keys: %s' % len(self.already_loaded))

        # Select unique key ids
        iterator = sess.query(MavenSignature.sig_key_id, sqlalchemy.func.count(MavenSignature.id).label('cnt')) \
            .group_by(MavenSignature.sig_key_id) \
            .all()

        for idx, obj in enumerate(iterator):
            key_id = int(obj.sig_key_id, 16)
            if key_id in self.already_loaded:
                continue

            self.keyset.add(key_id)
        logger.info('key set size to load: %s' % len(self.keyset))
        utils.silent_close(sess)

        # process PGP dump, fill in keys DB
        with open(self.args.json) as fh:
            s = self.session()
            for idx, line in enumerate(fh):
                try:

                    self.process_record(s, idx, line)
                    if idx % 15000 == 0:
                        s.flush()
                        s.commit()

                except Exception as e:
                    logger.error('Exception when processing line %s: %s' % (idx, e))
                    logger.debug(traceback.format_exc())

            utils.silent_close(s)

    def process_record(self, s, idx, line):
        """
        Processes one record from PGP dump
        :param idx: 
        :param line: 
        :return: 
        """
        rec = json.loads(line)
        master_key_id = int(utils.defvalkey(rec, 'key_id', '0'), 16)
        master_fingerprint = utils.defvalkey(rec, 'fingerprint')

        user_name = None
        if 'packets' in rec:
            # Phase 1 - info building
            packets = rec['packets']
            for packet in packets:
                if packet['tag_name'] == 'User ID':
                    user_name = utils.defvalkey(packet, 'user_id')

            # Phase 2 - sub packet processing
            for packet in packets:
                if packet['tag_name'] == 'Public-Subkey':
                    self.test_key(packet)
                    self.store_record(s, packet, master_key_id, master_fingerprint, user_name)

        self.test_key(rec)
        self.store_record(s, rec, None, None, user_name)

        if time.time() - self.last_report > 15:
            logger.debug(' .. report idx: %s, found: %s, keys added: %s, cur key: %016X '
                         % (idx, self.found, self.keys_added, master_key_id))
            self.last_report = time.time()

    def store_record(self, s, rec, master_id, master_fingerprint, user_name):
        """
        Stores master record
        :param rec: 
        :param master_id: 
        :param master_fingerprint: 
        :param user_name: 
        :return: 
        """
        key_id = int(utils.defvalkey(rec, 'key_id', '0'), 16)
        if key_id not in self.keyset:
            return

        n = utils.defvalkey(rec, 'n')
        e = utils.defvalkey(rec, 'e')
        algo_id = utils.defvalkey(rec, 'algo_id')
        creation_time = utils.defvalkey(rec, 'creation_time')
        fingerprint = utils.defvalkey(rec, 'fingerprint')

        key = PGPKey()
        key.key_id = utils.format_pgp_key(key_id)
        key.master_key_id = utils.format_pgp_key(master_id)
        key.master_fingerprint = master_fingerprint
        key.identity_email = user_name

        key.date_last_check = sqlalchemy.func.now()
        key.date_created = datetime.datetime.fromtimestamp(creation_time) if creation_time is not None else None
        key.fingerprint = fingerprint
        key.key_algorithm = algo_id
        key.key_modulus = n
        key.key_exponent = e
        s.add(key)
        self.keys_added += 1

    def test_key(self, rec):
        """
        Fingerprint test
        :param rec: 
        :return: 
        """
        if not self.args.sec:
            return
        if rec is not None:
            return

        key_id = utils.defvalkey(rec, 'key_id')
        n = utils.defvalkey(rec, 'n')
        if n is None:
            return

        x = self.fmagic.magic16([n])
        if len(x) > 0:
            self.found += 1
            logger.info('---------------!!!-------------- Keyid: %s' % key_id)

    def work(self):
        """
        Entry point after argument processing.
        :return: 
        """
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

        parser.add_argument('-c', dest='config', default=None,
                            help='JSON config file')

        parser.add_argument('-s', dest='sqlite', default=None,
                            help='SQlite DB')

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
        self.config_file = self.args.config
        self.sqlite_file = self.args.sqlite

        if self.args.sec:
            import sec
            self.fmagic = sec.Fprinter()

        if self.args.debug:
            coloredlogs.install(level=logging.DEBUG)

        self.work_db()


def main():
    app = MavenKeyExtract()
    app.main()


if __name__ == '__main__':
    main()

