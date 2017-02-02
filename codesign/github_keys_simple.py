#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
GitHub key downloader.
We use this for academic research on SSH keys entropy.
"""

import os
import sys
import inspect

from requests.auth import HTTPBasicAuth

currentdir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
parentdir = os.path.dirname(currentdir)
sys.path.insert(0, parentdir)


import requests
import logging
import coloredlogs
import traceback
import json
import argparse
import re
import urllib
import math
import hashlib
import time
import shutil
import multiprocessing
import time
import signal
import utils
import databaseutils

from database import GitHubKey
from database import Base as DB_Base


from lxml import html
from collections import OrderedDict, namedtuple
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

logger = logging.getLogger(__name__)
coloredlogs.install(level=logging.INFO)


# GitHub User ID & Name
GitHubUser = namedtuple('GitHubUser', ['user_id', 'user_name', 'user_type'])


class GitHubLoader(object):
    """
    GitHub SSH keys loader
    """

    USERS_URL = 'https://api.github.com/users?since=%s'
    KEYS_URL = 'https://api.github.com/users/%s/keys'

    def __init__(self, attempts=5, state=None, state_file=None):
        self.attempts = attempts
        self.total = None
        self.terminate = False
        self.since_id = 0
        self.last_users_count = None

        self.state = state
        self.state_file_path = state_file
        self.rate_limit_reset = None
        self.rate_limit_remaining = None

        self.db_config = None
        self.engine = None
        self.session = None

        if state is None and state_file is not None:
            with open(state_file, 'r') as fh:
                self.state = json.load(fh, object_pairs_hook=OrderedDict)
                logger.info('State loaded: %s' % os.path.abspath(self.state_file_path))

    def signal_handler(self, signal, frame):
        """
        Signal handler - terminate gracefully
        :param signal:
        :param frame:
        :return:
        """
        logger.info('CTRL+C pressed')
        self.terminate = True

    def init_db(self):
        """
        Initializes database engine & session.
        :return:
        """
        self.db_config = databaseutils.process_db_config(self.state['db'])

        from sqlalchemy import create_engine
        self.engine = create_engine(self.db_config.constr, pool_recycle=3600)

        from sqlalchemy.orm import sessionmaker
        self.session = sessionmaker()
        self.session.configure(bind=self.engine)

        DB_Base.metadata.create_all(self.engine)

    def load(self):
        """
        Loads page with attempts
        :return:
        """
        # Interrupt signals
        signal.signal(signal.SIGINT, self.signal_handler)

        # Resume last state
        if self.state is not None and 'since_id' in self.state:
            self.since_id = self.state['since_id']

        # Load all pages available
        while not self.terminate:

            if self.terminate:
                return None

            try:
                self.load_once_since()
                continue

            except KeyboardInterrupt:
                logger.info('Keyboard interrupt detected - setting to terminate')
                self.terminate = True
                return None

            except Exception as e:
                traceback.print_exc()
                time.sleep(3.0)

        return None

    def load_page(self, url):
        """
        Loads URL to json
        :param url:
        :return:
        """
        auth = None
        if 'github_token' in self.state and 'github_user' in self.state:
            auth = HTTPBasicAuth(self.state['github_user'], self.state['github_token'])

        for attempt in range(self.attempts):
            if self.terminate:
                raise Exception('Terminating')

            try:
                res = requests.get(url, timeout=10, auth=auth)
                headers = res.headers

                if res.status_code == 404:
                    logger.warning('URL not found: %s' % url)
                    return None, None, None

                self.rate_limit_reset = float(headers.get('X-RateLimit-Reset')) + 10
                self.rate_limit_remaining = int(headers.get('X-RateLimit-Remaining'))
                if self.rate_limit_remaining <= 1:
                    sleep_sec = self.rate_limit_reset - time.time()

                    logger.info('Rate limit exceeded, sleeping till: %d, it is %d seconds, %d minutes'
                                % (self.rate_limit_reset, sleep_sec, sleep_sec / 60.0))
                    self.sleep_interruptible(self.rate_limit_reset)
                    raise Exception('Rate limit exceeded')

                if res.status_code // 100 != 2:
                    res.raise_for_status()

                data = res.content
                if data is None:
                    raise Exception('Empty response')

                js = json.loads(data, object_pairs_hook=OrderedDict)
                return js, headers, res

            except Exception as e:
                logger.warning('Exception in loading page: %s, page: %s' % (e, url))

        logger.warning('Skipping url: %s' % url)
        return None, None, None

    def sleep_interruptible(self, until_time):
        """
        Interruptible sleep
        :param until_time:
        :return:
        """
        while time.time() <= until_time:
            time.sleep(1.0)
            if self.terminate:
                return

    def load_once_since(self):
        """
        Loads github user page with since var
        :param since:
        :return:
        """
        url = self.USERS_URL % self.since_id
        logging.info('Loading users: %s' % url)

        users, headers, res = self.load_page(url)
        self.last_users_count = len(users)

        max_id = 0L
        github_users = []
        for user in users:
            if 'id' not in user:
                logger.error('Field ID not found in user')
                continue

            github_user = GitHubUser(user_id=long(user['id']), user_name=user['login'], user_type=user['type'])
            github_users.append(github_user)

            if github_user.user_id > max_id:
                max_id = github_user.user_id

        # Load SSH keys here
        for user in github_users:
            if self.terminate:
                logger.info('Terminating')
                return

            keys = self.load_user_keys(user)
            if keys is None:
                continue

            for key in keys:
                s = self.session()
                self.store_key(user, key, s)
                try:
                    s.commit()
                except Exception as e:
                    logger.warning('Exception in storing key %s' % e)
                finally:
                    try:
                        s.close()
                    except:
                        pass

            # State update - user processed
            self.since_id = user.user_id
            self.flush_state()

        # Serialize - final round, all users loaded
        self.since_id = max_id
        self.flush_state()

    def store_key(self, user, key, s):
        """
        Stores user key to the database.
        :param user:
        :param key:
        :param s: current DB session
        :return:
        """
        try:
            key_id = long(key['id'])
            key_raw = key['key']

            key_type, key_val = key_raw.split(' ', 1)

            db_key = GitHubKey()
            db_key.id = key_id
            db_key.key_id = key_id
            db_key.key_type = key_type
            db_key.key_user_found = user.user_name
            db_key.key_user_id_found = user.user_id
            db_key.text_raw = key_raw

            try:
                key_obj = utils.load_ssh_pubkey(key_raw)
                if isinstance(key_obj, RSAPublicKey):
                    db_key.key_size = key_obj.key_size
                    numbers = key_obj.public_numbers()
                    db_key.key_modulus_dec = '%d' % numbers.n
                    db_key.key_modulus_hex = '%x' % numbers.n
                    db_key.key_exponent = numbers.e
            except Exception as e:
                logger.info('Exception during processing the key[%s]: %s' % (key_type, e))

            s.add(db_key)
            return 0

        except Exception as e:
            logger.warning('Exception during key store: %s' % e)
            return 1

    def load_user_keys(self, user):
        """
        Loads user keys page
        :param user:
        :return:
        """
        url = self.KEYS_URL % user.user_name
        if self.terminate:
            return None

        keys, headers, res = self.load_page(url)
        return keys

    def flush_state(self):
        """
        Flushes state/config to the state file
        :return:
        """
        self.state['since_id'] = self.since_id
        self.state['rate_limit_remaining'] = self.rate_limit_remaining
        self.state['rate_limit_reset'] = self.rate_limit_reset
        utils.flush_json(self.state, self.state_file_path)


def main():
    parser = argparse.ArgumentParser(description='Downloads GitHub SSH keys')
    parser.add_argument('-c', dest='config', default=None, help='JSON config/status file')
    parser.add_argument('--tmp', dest='tmp_dir', default='/tmp', help='temporary folder for analysis')

    args = parser.parse_args()
    json_path = args.config
    tmp_dir = args.tmp_dir

    l = GitHubLoader(state_file=json_path)
    l.init_db()
    l.load()


# Launcher
if __name__ == "__main__":
    main()


