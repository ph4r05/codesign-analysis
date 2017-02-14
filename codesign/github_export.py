#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
GitHub data exporter.
"""

import os
import sys
import inspect
import resource

currentdir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
parentdir = os.path.dirname(currentdir)
sys.path.insert(0, parentdir)


import requests
import logging
import coloredlogs
import calendar
import traceback
import json
import argparse
import re
import math
import random
import time
import shutil
import multiprocessing
import time
import signal
import utils
import databaseutils
import collections
import threading
from threading import Lock as Lock
import types
import Queue
from blessed import Terminal
from cmd2 import Cmd

from database import GitHubKey, GitHubUser as GitHubUserDb
from database import Base as DB_Base
from sqlalchemy.orm import scoped_session
import sqlalchemy as salch

import gc
import mem_top
from collections import OrderedDict, namedtuple
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

logger = logging.getLogger(__name__)
coloredlogs.install(level=logging.DEBUG)


class GitHubExporter(object):
    """
    GitHub Exporter
    """

    def __init__(self, config_file=None, sqlite=None, use_json=False, *args, **kwargs):
        self.t = Terminal()

        self.terminate = False

        self.config = None
        self.config_file = config_file
        self.sqlite_file = sqlite
        self.use_json = use_json

        self.stop_event = threading.Event()
        self.db_config = None
        self.engine = None
        self.session = None

        self.sqlite_engine = None
        self.sqlite_session = None

    def signal_handler(self, signal, frame):
        """
        Signal handler - terminate gracefully
        :param signal:
        :param frame:
        :return:
        """
        logger.info('CTRL+C pressed')
        self.trigger_stop()

    def trigger_stop(self):
        """
        Sets terminal conditions to true
        :return:
        """
        self.terminate = True
        self.stop_event.set()

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
        self.db_config = databaseutils.process_db_config(self.config['db'])

        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker, scoped_session
        self.engine = create_engine(self.db_config.constr, pool_recycle=3600)
        self.session = scoped_session(sessionmaker(bind=self.engine))

        # Make sure tables are created
        DB_Base.metadata.create_all(self.engine)

        if self.sqlite_file is not None:
            dbname = 'sqlite:///%s' % self.sqlite_file
            self.sqlite_engine = create_engine(dbname, echo=False)
            self.sqlite_session = scoped_session(sessionmaker(bind=self.sqlite_engine))
            DB_Base.metadata.create_all(self.sqlite_engine)
            logger.info('Using SQLite %s' % self.sqlite_engine)

    def work(self):
        logger.info('Starting...')
        self.init_config()
        self.init_db()
        logger.info('Database initialized')

        sess = self.session()
        buff = []
        for obj in sess.query(GitHubKey).yield_per(1000):  # .limit(20):
            sess.expunge(obj)
            buff.append(obj)

            if self.use_json:
                js = OrderedDict()
                js['id'] = obj.id
                js['last_check'] = calendar.timegm(obj.date_last_check.timetuple())
                js['discovered'] = calendar.timegm(obj.date_discovered.timetuple())
                js['type'] = obj.key_type
                js['size'] = obj.key_size
                js['mod'] = obj.key_modulus_hex
                js['e'] = obj.key_exponent
                js['user'] = obj.key_user_found
                js['user_id'] = obj.key_user_id_found
                js['raw'] = obj.text_raw
                print(json.dumps(js))

            if len(buff) > 1000:
                self.flush_sqlite(buff)
                buff = []

        # Final flush
        self.flush_sqlite(buff)
        buff = []

    def flush_sqlite(self, buff):
        if len(buff) == 0:
            return
        if self.sqlite_file is None:
            return

        s = self.sqlite_session()
        for elem in buff:
            s.merge(elem)

        logger.debug('Committing %d elems %s' % (len(buff), s))
        s.flush()
        s.commit()
        utils.silent_close(s)


def main():
    args_src = sys.argv
    parser = argparse.ArgumentParser(description='Export GitHub SSH keys')
    parser.add_argument('-c', dest='config', default=None, help='JSON config file')
    parser.add_argument('-s', dest='sqlite', default=None, help='SQlite file')
    parser.add_argument('--json', dest='use_json', default=False, action='store_const', const=True,
                        help='Load only users list')

    args = parser.parse_args(args=args_src[1:])
    config_file = args.config

    if args.sqlite is not None:
        if os.path.exists(args.sqlite):
            os.remove(args.sqlite)

    sys.argv = [args_src[0]]
    logger.info('GitHub loader started, args: %s' % args)
    l = GitHubExporter(config_file=config_file, sqlite=args.sqlite, use_json=args.use_json)
    l.work()
    sys.argv = args_src


# Launcher
if __name__ == "__main__":
    main()




