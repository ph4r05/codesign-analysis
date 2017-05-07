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
import math
from collections import OrderedDict

from database import GitHubKey
from maven_base import Artifact, ArtifactVer, DepMapper
from pgpdump.data import AsciiData
from pgpdump.packet import SignaturePacket, PublicKeyPacket, PublicSubkeyPacket, UserIDPacket

import sqlalchemy
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session, Session
from database import MavenArtifact, MavenSignature, PGPKey
from database import Base as DB_Base

logger = logging.getLogger(__name__)
coloredlogs.install(level=logging.INFO)


class GitHubFprint(object):
    """
    GitHub fingerprinting
    """

    def __init__(self):
        self.args = None
        self.fmagic = None

        self.config = None
        self.config_file = None

        self.db_config = None
        self.engine = None
        self.session = None
        self.session2 = None

        self.last_report = 0
        self.last_flush = 0
        self.found = 0

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
        self.session2 = scoped_session(sessionmaker(bind=self.engine))

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
        ctr = 0

        # Select all existing key ids
        all_keys = sess.query(GitHubKey).yield_per(1000)
        for rec in all_keys:
            n = rec.key_modulus_hex
            if n is None or len(n) == 0:
                continue

            n = utils.strip_hex_prefix(n)
            x = self.fmagic.magic16([n])
            is_interesting = len(x) > 0
            if rec.is_interesting != is_interesting:
                s2 = self.session2()
                try:
                    rec.is_interesting = int(is_interesting)
                    s2.merge(rec)
                    s2.commit()

                    logger.info('Got it for user %s, id: %s' % (rec.key_user_found, rec.id))
                except Exception as e:
                    logger.error('Exception %s' % e)
                    logger.debug(traceback.format_exc())
                finally:
                    s2.close()

            ctr += 1

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

        parser.add_argument('--debug', dest='debug', default=False, action='store_const', const=True,
                            help='Debugging logging')

        parser.add_argument('--sec', dest='sec', default=False, action='store_const', const=True,
                            help='sec')

        parser.add_argument('--sec-mvn', dest='sec_mvn', default=False, action='store_const', const=True,
                            help='sec')

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
    app = GitHubFprint()
    app.main()


if __name__ == '__main__':
    main()

