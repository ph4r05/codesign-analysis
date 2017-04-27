#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Extracting maven keys identified by key IDs from the json file using big PGP dump 
"""

from queue import Queue, Empty as QEmpty
import re
import os
import json
import types
import argparse
import logging
import coloredlogs
import traceback
import time
import datetime
import utils
import threading
import versions as vv
import databaseutils
from collections import OrderedDict
from pgpdump.data import AsciiData
from pgpdump.packet import SignaturePacket, PublicKeyPacket, PublicSubkeyPacket, UserIDPacket

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
        self.last_flush = 0
        self.found = 0
        self.keys_added = 0
        self.keyset = set()
        self.keyset_found = set()
        self.no_key_id = 0
        self.already_loaded = set()
        self.flat_test_res = []

        self.all_keys_inserted = False
        self.stop_event = threading.Event()
        self.local_data = threading.local()
        self.queue = Queue()
        self.pgp_downloaded = Queue()
        self.workers = []

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
        if self.args.json:
            with open(self.args.json) as fh:
                s = self.session()
                for idx, line in enumerate(fh):
                    try:

                        self.process_record(s, idx, line)
                        if time.time() - self.last_flush > 5:
                            s.flush()
                            s.commit()
                            self.last_flush = time.time()

                    except Exception as e:
                        logger.error('Exception when processing line %s: %s' % (idx, e))
                        logger.debug(traceback.format_exc())

                utils.silent_close(s)

        # download missing keys
        if self.args.download_missing:
            self.download_missing()

        # fprint keys
        for x in self.flat_test_res:
            logger.info('Interesting keys %s: %s' % (x[0], x[1]))

        # keys not found:
        not_found = sorted([x for x in list(self.keyset) if x not in self.already_loaded])
        logger.info('Keys not found (%s): %s '
                    % (len(not_found), json.dumps([utils.format_pgp_key(x) for x in not_found])))

    def download_missing(self):
        """
        Download missing keys from PGP key server
        :return: 
        """
        not_found = sorted([x for x in list(self.keyset) if x not in self.already_loaded])

        # Kick off the workers
        for worker_idx in range(self.args.threads):
            t = threading.Thread(target=self.pgp_download_main, args=(worker_idx,))
            t.setDaemon(True)
            t.start()

        for x in not_found:
            self.queue.put(x)

        self.all_keys_inserted = True

        # processor / consumer
        t = threading.Thread(target=self.pgp_process_downloaded_keys, args=())
        t.setDaemon(True)
        t.start()

        # Wait on all jobs being finished
        self.queue.join()
        self.pgp_downloaded.join()

        # All data processed, terminate bored workers
        self.stop_event.set()

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

        flat_keys = [rec]
        user_names = []

        # Phase 1 - info extraction
        if 'packets' in rec:
            for packet in rec['packets']:
                if packet['tag_name'] == 'User ID':
                    utils.append_not_none(user_names, utils.defvalkey(packet, 'user_id'))
                elif packet['tag_name'] == 'Public-Subkey':
                    flat_keys.append(packet)

        self.test_flat_keys(flat_keys)
        self.store_record(s, rec, None, None, user_names, None)

        # Phase 2 - sub packet processing
        if 'packets' in rec:
            for packet in rec['packets']:
                if packet['tag_name'] == 'Public-Subkey':
                    self.store_record(s, packet, master_key_id, master_fingerprint, user_names, rec)

        if time.time() - self.last_report > 15:
            logger.debug(' .. report idx: %s, found: %s, keys added: %s, cur key: %016X '
                         % (idx, self.found, self.keys_added, master_key_id))
            self.last_report = time.time()

    def store_record(self, s, rec, master_id, master_fingerprint, user_names, master_rec):
        """
        Stores master record
        :param rec: 
        :param master_id: 
        :param master_fingerprint: 
        :param user_names: 
        :param master_rec: 
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
        key.identity = utils.first(user_names)
        key.identities_json = json.dumps(user_names)

        key.date_last_check = sqlalchemy.func.now()
        key.date_created = datetime.datetime.fromtimestamp(creation_time) if creation_time is not None else None
        key.fingerprint = fingerprint
        key.key_algorithm = algo_id
        key.key_modulus = n
        key.key_exponent = e
        key.is_interesting = self.test_key(rec=rec) or self.test_key(master_rec)

        s.add(key)
        self.keys_added += 1
        self.already_loaded.add(key_id)

    def test_flat_keys(self, flat_keys):
        """
        Tests all keys in the array
        :param flat_keys: 
        :return: 
        """
        if not self.args.sec_mvn:
            return

        flat_key_ids = [int(utils.defvalkey(x, 'key_id', '0'), 16) for x in flat_keys]
        if any([(x in self.already_loaded or x in self.keyset) for x in flat_key_ids]):
            tested = [self.test_key(x) for x in flat_keys]
            if any(tested):
                keys_hex = [utils.format_pgp_key(x) for x in flat_key_ids]
                logger.info('------- interesting map: %s for key ids %s' % (tested, keys_hex))
                self.flat_test_res.append((tested, keys_hex))

    def test_key(self, rec=None):
        """
        Fingerprint test
        :param rec: 
        :return: 
        """
        if not self.args.sec:
            return False

        if rec is None:
            return False

        key_id = utils.defvalkey(rec, 'key_id')
        n = utils.defvalkey(rec, 'n')
        return self.test_mod(n, key_id)

    def test_mod(self, n, key_id=None):
        """
        Mod testing - fprint
        :param n: 
        :return: 
        """
        if n is None:
            return False
        if self.fmagic is None:
            return False
        if isinstance(n, (types.IntType, types.LongType)):
            n = '%x' % n

        n = n.strip()
        n = utils.strip_hex_prefix(n)

        x = self.fmagic.magic16([n])
        if len(x) > 0:
            self.found += 1
            if key_id is not None:
                logger.info('---------------!!!-------------- Keyid: %s' % key_id)
            return True
        return False

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

    def pgp_download_main(self, idx):
        """
        Producer / downloader thread.
        Downloads PGP keys from the key server. 
        :param idx: 
        :return: 
        """
        self.local_data.idx = idx
        logger.info('Worker %02d started' % idx)

        while not self.stop_event.is_set():
            job = None
            try:
                job = self.queue.get(True, timeout=1.0)
            except QEmpty:
                if self.all_keys_inserted:
                    return
                time.sleep(0.1)
                continue

            try:
                # Process job in try-catch so it does not break worker
                logger.info('[%02d] Processing job %s' % (idx, job))
                the_key = utils.get_pgp_key(job)
                self.pgp_downloaded.put((job, the_key))

            except Exception as e:
                logger.error('Exception in processing job %s: %s' % (e, job))
                logger.debug(traceback.format_exc())

            finally:
                self.queue.task_done()
        logger.info('Worker %02d terminated' % idx)

    def pgp_process_downloaded_keys(self):
        """
        Consumer thread.
        Process all downloaded elements from the queue.
        :return: 
        """
        while not self.stop_event.is_set():
            job = None
            try:
                job = self.pgp_downloaded.get(True, timeout=1.0)
            except QEmpty:
                time.sleep(0.1)
                continue

            s = self.session()
            try:
                self.pgp_process_key(s, job)
                s.flush()
                s.commit()

            except Exception as e:
                logger.error('Exception in processing job %s: %s' % (e, job))
                logger.debug(traceback.format_exc())

            finally:
                self.pgp_downloaded.task_done()
                utils.silent_close(s)

        logger.info('PGP downloaded processor terminated')

    def pgp_process_key(self, s, data):
        """
        Process downloaded key
        :param key: 
        :return: 
        """
        key_id, key = data

        pgp_key_data = AsciiData(key)
        packets = list(pgp_key_data.packets())

        db_key = PGPKey()
        db_key.date_downloaded = sqlalchemy.func.now()
        db_key.date_last_check = sqlalchemy.func.now()
        db_key.key_id = utils.format_pgp_key(key_id)
        db_key.key_file = key

        identities = []
        pubkeys = []
        sig_cnt = 0
        for idx, packet in enumerate(packets):
            if isinstance(packet, PublicKeyPacket):
                pubkeys.append(packet)
            elif isinstance(packet, PublicSubkeyPacket):
                pubkeys.append(packet)
            elif isinstance(packet, UserIDPacket):
                identities.append(packet)
            elif isinstance(packet, SignaturePacket):
                sig_cnt += 1

        # Names / identities
        ids_arr = []
        for packet in identities:
            db_key.identity_email = packet.user_email
            db_key.identity_name = packet.user_name
            db_key.identity = '%s <%s>' % (packet.user_name, packet.user_email)
            idjs = OrderedDict()
            idjs['name'] = packet.user_name
            idjs['email'] = packet.user_email
            ids_arr.append(idjs)
        db_key.identities_json = json.dumps(ids_arr)
        db_key.signatures_count = sig_cnt

        # Public keys processing
        key_found = False
        is_interesting = False
        for packet in pubkeys:
            cur_key_id = int(utils.strip_hex_prefix(packet.key_id), 16)

            if cur_key_id == key_id:
                key_found = True
                db_key.fingerprint = '%s' % packet.fingerprint
                db_key.key_version = int(packet.pubkey_version)
                db_key.key_algorithm = '%s' % packet.pub_algorithm
                db_key.date_created = packet.creation_time
                db_key.date_expires = packet.expiration_time

                if packet.modulus is not None:
                    db_key.key_modulus = '%x' % packet.modulus
                    is_interesting |= self.test_mod(packet.modulus)

                if packet.exponent is not None:
                    db_key.key_exponent = '%x' % packet.exponent

            elif not isinstance(packet, PublicSubkeyPacket):
                db_key.master_key_id = utils.format_pgp_key(cur_key_id)
                db_key.master_fingerprint = '%s' % packet.fingerprint
                if packet.modulus is not None:
                    is_interesting |= self.test_mod(packet.modulus)

        db_key.is_interesting = is_interesting
        if key_found:
            s.add(db_key)
            self.keys_added += 1
            self.already_loaded.add(key_id)
        else:
            logger.warning('Key not found: %s' % utils.format_pgp_key(key_id))

        # Global testing of keys
        tested_keys = [self.test_mod(x.modulus) for x in pubkeys]
        if any(tested_keys):
            keys_hex = [utils.format_pgp_key(x.key_id) for x in pubkeys]
            logger.info('------- interesting map: %s for key ids %s' % (tested_keys, keys_hex))
            self.flat_test_res.append((tested_keys, keys_hex))

    def main(self):
        """
        Main entry point
        :return: 
        """
        parser = argparse.ArgumentParser(description='Maven PGP key processor')

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

        parser.add_argument('--sec-mvn', dest='sec_mvn', default=False, action='store_const', const=True,
                            help='sec')

        parser.add_argument('--download-missing', dest='download_missing', default=False, action='store_const', const=True,
                            help='downloads missing pgp keys from the key server')

        parser.add_argument('-t', dest='threads', default=1, type=int,
                            help='Number of threads to use for downloading the keys')

        parser.add_argument('--keys', dest='keys', default=None,
                            help='JSON array with key IDs')

        parser.add_argument('--json', dest='json', default=None,
                            help='Big json file from pgp dump')

        self.args = parser.parse_args()
        self.config_file = self.args.config
        self.sqlite_file = self.args.sqlite

        if self.args.sec_mvn:
            self.args.sec = True

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

