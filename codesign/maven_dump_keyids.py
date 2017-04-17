#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Simple maven script for dumping unique PGP key ids to the json.
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


class MavenKeyIdDump(object):
    """
    Produces simple json array of unique key ids.
    
    For more advanced setup you may export local snapshot of the DB to the sqlite and compute with the whole
    database on the cluster. https://github.com/dumblob/mysql2sqlite
    """
    def __init__(self):
        self.args = None
        self.db_config = None
        self.engine = None
        self.session = None

        self.config_file = None
        self.config = None

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

    def work(self):
        """
        Entry point after argument processing.
        :return: 
        """
        self.config_file = self.args.config
        self.init_config()
        self.init_db()

        s = self.session()
        js_res = []
        try:
            res = s.query(MavenSignature.sig_key_id).group_by(MavenSignature.sig_key_id).all()
            for keyrec in res:
                js_res.append(keyrec.sig_key_id)
            
            js_res.sort()
            print(json.dumps(js_res))

        except Exception as e:
            logger.error('Exception in dump: %s' % e)
            logger.debug(traceback.format_exc())
        finally:
            utils.silent_close(s)

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

        parser.add_argument('--config', dest='config', default=None,
                            help='Config file')

        self.args = parser.parse_args()

        if self.args.debug:
            coloredlogs.install(level=logging.DEBUG)

        self.work()


def main():
   app = MavenKeyIdDump()
   app.main()


if __name__ == '__main__':
    main()

