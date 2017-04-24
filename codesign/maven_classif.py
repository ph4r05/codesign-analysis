#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Maven data classification JSON exporter.

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


class MavenClassif(object):
    """
    Maven data classification JSON exporter.
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
        self.keyset = set()
        self.keyset_found = set()
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

        resfile = os.path.join(self.args.data_dir, 'maven-dataset.json')
        with open(resfile, 'w') as resfw:
            sess = self.session()

            # Load all existing key ids
            existing_keys = sess.query(PGPKey).all()
            for rec in existing_keys:
                key_id = int(rec.key_id, 16)

                # Load all deps.
                deps = sess.query(MavenSignature) \
                    .filter(MavenSignature.sig_key_id == utils.format_pgp_key(key_id)) \
                    .all()

                js = OrderedDict()
                js['source'] = [rec.identity,
                                rec.date_created.strftime('%Y-%m-%d') if rec.date_created is not None else '']
                js['key_id'] = rec.key_id
                js['fprint'] = rec.fingerprint

                js['m_key_id'] = rec.master_key_id
                js['m_fprint'] = rec.master_fingerprint

                js['e'] = rec.key_exponent
                js['n'] = rec.key_modulus

                sigs = []
                for dep in deps:
                    sigs.append(utils.maven_package_id(dep.group_id, dep.artifact_id, dep.version_id))

                js['deps'] = len(sigs)
                js['info'] = {'deps': sigs}
                resfw.write(json.dumps(js) + '\n')

    def main(self):
        """
        Main entry point
        :return: 
        """
        parser = argparse.ArgumentParser(description='Maven data exporter for classification')

        parser.add_argument('-c', dest='config', default=None,
                            help='JSON config file')

        parser.add_argument('--data', dest='data_dir', default='.',
                            help='Data directory output')

        parser.add_argument('--debug', dest='debug', default=False, action='store_const', const=True,
                            help='Debugging logging')

        self.args = parser.parse_args()
        self.config_file = self.args.config
        self.sqlite_file = self.args.sqlite

        if self.args.debug:
            coloredlogs.install(level=logging.DEBUG)

        self.work_db()


def main():
    app = MavenClassif()
    app.main()


if __name__ == '__main__':
    main()




