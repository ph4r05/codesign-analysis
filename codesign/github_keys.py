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
import collections
import threading
from threading import Lock as Lock
import Queue
from blessed import Terminal
from cmd2 import Cmd

from database import GitHubKey
from database import Base as DB_Base
from sqlalchemy.orm import scoped_session


from lxml import html
from collections import OrderedDict, namedtuple
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

logger = logging.getLogger(__name__)
coloredlogs.install(level=logging.INFO)


# GitHub User ID & Name
GitHubUser = namedtuple('GitHubUser', ['user_id', 'user_name', 'user_type'])


class AccessResource(object):
    """
    Represents one access token
    """

    def __init__(self, usr=None, token=None, remaining=None, reset_time=None, idx=0, *args, **kwargs):
        self.idx = idx
        self.usr = usr
        self.token = token
        self.remaining = remaining
        self.reset_time = reset_time

    def __cmp__(self, other):
        """
        Compare operation for priority queue.
        :param other:
        :return:
        """
        if self.remaining is None and other.remaining is None:
            return self.idx - other.idx
        elif self.remaining is None:
            return -1
        elif other.remaining is None:
            return 1
        else:
            return other.remaining - self.remaining

    def to_json(self):
        js = collections.OrderedDict()
        js['usr'] = self.usr
        js['remaining'] = self.remaining
        js['reset_time'] = self.reset_time
        return js


class DownloadJob(object):
    """
    Represents link to download
    """

    TYPE_USERS = 1
    TYPE_KEYS = 2

    def __init__(self, url=None, jtype=TYPE_USERS, user=None, *args, **kwargs):
        self.url = url
        self.type = jtype
        self.user = user
        self.fail_cnt = 0
        self.last_fail = 0

    def to_json(self):
        js = collections.OrderedDict()
        js['url'] = self.url
        js['type'] = self.type
        js['fail_cnt'] = self.fail_cnt
        js['last_fail'] = self.last_fail
        if self.user is not None:
            js['user_id'] = self.user.user_id
            js['user_name'] = self.user.user_name
            js['user_type'] = self.user.user_type
        return js

    @classmethod
    def from_json(cls, js):
        tj = cls()
        tj.url = js['url']
        tj.type = js['type']
        tj.fail_cnt = js['fail_cnt']
        tj.last_fail = js['last_fail']
        if 'user_id' in js:
            tj.user = GitHubUser(user_id=js['user_id'], user_name=js['user_name'], user_type=js['user_type'])
        return tj


class GitHubLoader(Cmd):
    """
    GitHub SSH keys loader
    """
    prompt = '$> '

    USERS_URL = 'https://api.github.com/users?since=%s'
    KEYS_URL = 'https://api.github.com/users/%s/keys'

    def __init__(self, attempts=5, threads=1, state=None, state_file=None, config_file=None, audit_file=None, *args, **kwargs):
        Cmd.__init__(self, *args, **kwargs)
        self.t = Terminal()

        self.attempts = int(attempts)
        self.total = None
        self.terminate = False
        self.since_id = 0
        self.last_users_count = None

        self.state = state
        self.state_file_path = state_file
        self.rate_limit_reset = None
        self.rate_limit_remaining = None

        self.config = None
        self.config_file = config_file

        self.audit_file = audit_file
        self.audit_records_buffered = []
        self.audit_lock = Lock()

        self.stop_event = threading.Event()
        self.threads = int(threads)
        self.link_queue = Queue.Queue()  # Store links to download here
        self.worker_threads = []

        self.state_thread = None
        self.state_thread_lock = Lock()

        self.resources_list = []
        self.resources_queue = Queue.PriorityQueue()
        self.resources_queue_lock = Lock()
        self.local_data = None

        self.db_config = None
        self.engine = None
        self.session = None

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

    def do_quit(self, arg):
        self.trigger_stop()
        logger.info('Waiting for thread termination')

        time.sleep(1)
        logger.info('Quitting')
        return Cmd.do_quit(self, arg)

    def init_config(self):
        """
        Loads config & state files
        :return:
        """
        if self.state_file_path is not None and os.path.exists(self.state_file_path):
            with open(self.state_file_path, 'r') as fh:
                self.state = json.load(fh, object_pairs_hook=OrderedDict)
                logger.info('State loaded: %s' % os.path.abspath(self.state_file_path))

        with open(self.config_file, 'r') as fh:
            self.config = json.load(fh, object_pairs_hook=OrderedDict)
            logger.info('Config loaded: %s' % os.path.abspath(self.config_file))

            if 'since_id' in self.config:
                self.since_id = self.config['since_id']

            # Process resources
            if 'res' in self.config:
                for idx, res in enumerate(self.config['res']):
                    r = AccessResource(usr=res['usr'], token=res['token'], idx=idx)
                    self.resources_list.append(r)
                    self.resources_queue.put(r)
            else:
                # unauth
                r = AccessResource(usr=None, token=None)
                self.resources_list.append(r)
                self.resources_queue.put(r)

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

    def init_workers(self):
        """
        Initialize worker threads
        :return:
        """
        logger.info('Starting %d working threads' % self.threads)
        for idx in range(self.threads):
            t = threading.Thread(target=self.work_thread_main, args=(idx, ))
            self.worker_threads.append(t)

        # Kick-off all threads
        for t in self.worker_threads:
            t.start()

        logger.info('Worker threads started')

    def work(self):
        """
        Main thread work method
        :return:
        """
        # Interrupt signals
        signal.signal(signal.SIGINT, self.signal_handler)

        self.init_config()
        self.init_db()

        # Resume last state
        self.state_resume()

        # Monitor threads.
        self.state_thread = threading.Thread(target=self.state_main, args=())
        self.state_thread.start()

        # If there is no link to process - create from since.
        if self.link_queue.qsize() == 0:
            job = DownloadJob(url=self.USERS_URL % self.since_id, jtype=DownloadJob.TYPE_USERS)
            self.link_queue.put(job)
            logger.info('Kickoff link added: %s' % job.url)

        # Worker threads
        self.init_workers()

        logger.info('Main thread started %s %s %s' % (os.getpid(), os.getppid(), threading.current_thread()))
        self.cmdloop()

        logger.info('Waiting termination of slave threads')

        # Wait here for termination of all workers and monitors.
        self.state_thread.join()
        for t in self.worker_threads:
            t.join()

        logger.info('Terminating main thread')
        return None

    def work_thread_main(self, idx):
        """
        Worker thread main loop
        :return:
        """
        self.local_data = threading.local()
        self.local_data.idx = idx

        while not self.terminate and not self.stop_event.is_set():
            self.interruptible_sleep_delta(0.1)

            # Get credential to process link with
            resource = self.resource_allocate()
            if resource is None:
                continue

            # We have resource, now get the job
            job = None
            try:
                job = self.link_queue.get(True, timeout=1.0)
            except Queue.Empty:
                self.resource_return(resource)
                continue

            # If job last fail is too recent - put again back to queue
            if time.time() - job.last_fail < 3.0:
                self.link_queue.put(job)  # re-insert to the back of the queue for later processing
                self.resource_return(resource)
                continue

            # Job processing starts here - fetch data page with the resource.
            js_data = None
            try:
                self.local_data.job = job
                self.local_data.resource = resource
                js_data, headers, raw_response = self.load_page_local()

            except Exception as e:
                logger.error('Exception in processing job: %s' % job.url)
                self.on_job_failed(job)
                continue

            finally:
                self.resource_return(resource)
                self.local_data.resource = None
                self.local_data.last_usr = resource.usr
                self.local_data.last_remaining = resource.remaining

            # Process downloaded data here.
            try:
                if js_data is None:
                    self.audit_log('404', job.url, jtype=job.type)
                    self.flush_audit()
                    continue

                if job.type == DownloadJob.TYPE_USERS:
                    self.process_users_data(job, js_data, headers, raw_response)
                else:
                    self.process_keys_data(job, js_data, headers, raw_response)

            except Exception as e:
                logger.error('Unexpected exception, processing type %s, link %s: %s' % (job.type, job.url, e))
                traceback.print_exc()
                self.on_job_failed(job)

        pass
        logger.info('Terminating worker thread %d' % idx)

    def on_job_failed(self, job):
        """
        If job failed, this teaches it how to behave
        :param job:
        :return:
        """
        job.fail_cnt += 1
        job.last_fail = time.time()

        # if failed too many times - log and discard.
        if job.fail_cnt > 10:
            self.audit_log('too-many-fails', job.url, jtype=job.type)
            self.flush_audit()
        else:
            self.link_queue.put(job)  # re-insert to the queue for later processing

    def load_page_local(self):
        """
        Loads page stored in thread local
        :return:
        """

        auth = None
        resource = self.local_data.resource
        if resource.usr is not None:
            auth = HTTPBasicAuth(resource.usr, resource.token)

        job = self.local_data.job

        res = requests.get(job.url, timeout=10, auth=auth)
        headers = res.headers

        resource.reset_time = float(headers.get('X-RateLimit-Reset'))
        resource.remaining = int(headers.get('X-RateLimit-Remaining'))

        if res.status_code == 404:
            logger.warning('URL not found: %s' % job.url)
            return None, None, None

        if res.status_code // 100 != 2:
            res.raise_for_status()

        data = res.content
        if data is None:
            raise Exception('Empty response')

        js = json.loads(data, object_pairs_hook=OrderedDict)
        return js, headers, res

    def process_users_data(self, job, js, headers, raw_response):
        """
        Process user data - produce keys links + next user link
        :param job:
        :param js:
        :param headers:
        :param raw_response:
        :return:
        """
        max_id = 0
        github_users = []
        for user in js:
            if 'id' not in user:
                logger.error('Field ID not found in user')
                continue

            github_user = GitHubUser(user_id=long(user['id']), user_name=user['login'], user_type=user['type'])
            github_users.append(github_user)

            key_url = self.KEYS_URL % github_user.user_name
            new_job = DownloadJob(url=key_url, jtype=DownloadJob.TYPE_KEYS, user=github_user)
            self.link_queue.put(new_job)

            if github_user.user_id > max_id:
                max_id = github_user.user_id

        # Link with the maximal user id
        users_url = self.USERS_URL % max_id
        new_job = DownloadJob(url=users_url, jtype=DownloadJob.TYPE_USERS)
        self.link_queue.put(new_job)

        logger.info('[%02d, usr=%s, remaining=%s] Processed users link %s, Next since: %s. New users: [%s]'
                    % (self.local_data.idx, self.local_data.last_usr, self.local_data.last_remaining,
                       len(github_users)+1, max_id, ', '.join([str(x.user_name) for x in github_users])))

    def process_keys_data(self, job, js, headers, raw_response):
        """
        Processing key loaded data
        :param job:
        :param js:
        :param headers:
        :param raw_response:
        :return:
        """
        for key in js:
            s = self.session()
            self.store_key(job.user, key, s)
            try:
                s.commit()
            except Exception as e:
                logger.warning('Exception in storing key %s' % e)
            finally:
                utils.silent_close(s)

    def resource_allocate(self, blocking=True, timeout=1.0):
        """
        Takes resource from the pool.
        If the resource has low remaining credit, thread is suspended to re-charge.
        :return: resource or None if not available in the time
        """
        try:
            resource = self.resources_queue.get(True, timeout=1.0)
            if resource.remaining is not None and resource.remaining <= self.threads + 2:
                sleep_sec = resource.reset_time - time.time()
                sleep_sec += 120  # extra 2 minutes to avoid problems with resources

                logger.info('Rate limit exceeded on resource %s, sleeping till: %d, it is %d seconds, %d minutes'
                            % (resource.usr, resource.reset_time, sleep_sec, sleep_sec / 60.0))
                self.sleep_interruptible(self.rate_limit_reset)
                logger.info('Resource sleep finished %s' % resource.usr)

            return resource

        except Queue.Empty:
            return None

    def resource_return(self, res):
        """
        Returns resource to the pool
        :param res:
        :return:
        """
        self.resources_queue.put(res)

    def sleep_interruptible(self, until_time):
        """
        Interruptible sleep
        :param until_time:
        :return:
        """
        while time.time() <= until_time:
            time.sleep(1.0)
            if self.terminate or self.stop_event.is_set():
                return

    def interruptible_sleep_delta(self, sleep_time):
        """
        Sleeps the current thread for given amount of seconds, stop event terminates the sleep - to exit the thread.
        :param sleep_time:
        :return:
        """
        if sleep_time is None:
            return

        sleep_time = float(sleep_time)

        if sleep_time == 0:
            return

        sleep_start = time.time()
        while not self.stop_event.is_set() and not self.terminate:
            time.sleep(0.1)
            if time.time() - sleep_start >= sleep_time:
                return

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

    def flush_state(self):
        """
        Flushes state/config to the state file
        :return:
        """
        self.state['since_id'] = self.since_id
        self.state['rate_limit_remaining'] = self.rate_limit_remaining
        self.state['rate_limit_reset'] = self.rate_limit_reset
        utils.flush_json(self.state, self.state_file_path)

    #
    # Auditing - errors, problems for further analysis
    #

    def audit_log(self, evt=None, link=None, jtype=None):
        """
        Appends audit log to the buffer. Lock protected.
        :param evt:
        :param link:
        :return:
        """
        log = collections.OrderedDict()
        log['time'] = time.time()
        log['evt'] = evt
        log['jtype'] = jtype
        log['link'] = link
        with self.audit_lock:
            self.audit_records_buffered.append(log)

    def flush_audit(self):
        """
        Flushes audit logs to the JSON append only file.
        Routine protected by the lock (no new audit record can be inserted while holding the lock)
        :return:
        """
        if self.audit_file is None:
            self.audit_records_buffered = []
            return

        self.audit_lock.acquire()
        try:
            if len(self.audit_records_buffered) == 0:
                return
            with open(self.audit_file, 'a') as fa:
                for x in self.audit_records_buffered:
                    fa.write(json.dumps(x) + "\n")
            self.audit_records_buffered = []
        except Exception as e:
            logger.error('Exception in audit log dump %s' % e)
        finally:
            self.audit_lock.release()

    #
    # State save / resume
    #

    def state_main(self):
        """
        State thread - periodical dump of the queues.
        :return:
        """
        logger.info('State thread started %s %s %s' % (os.getpid(), os.getppid(), threading.current_thread()))
        try:
            while not self.stop_event.is_set() and not self.terminate:
                try:
                    # Dump stats each x seconds
                    # Sleep is here because of dumping the state for the last time just before program quits.
                    self.interruptible_sleep_delta(10)

                    js_q = collections.OrderedDict()
                    js_q['gen'] = time.time()
                    js_q['link_size'] = self.link_queue.qsize()
                    js_q['since_id'] = self.since_id

                    # Stats.
                    js_q['resource_stats'] = [x.to_json() for x in list(self.resources_list)]

                    # Finally - the queue
                    js_q['link_queue'] = [x.to_json() for x in list(self.link_queue.queue)]
                    utils.flush_json(js_q, self.state_file_path)

                except Exception as e:
                    traceback.print_exc()
                    logger.error('Exception in state: %s', e)

        except Exception as e:
            traceback.print_exc()
            logger.error('Exception in state: %s' % e)

        finally:
            pass

        logger.info('State loop terminated')

    def state_resume(self):
        """
        Attempts to resume the queues from the monitoring files
        :return:
        """
        try:
            if self.state is None:
                return

            if 'since_id' in self.state:
                self.since_id = self.state['since_id']

            if 'link_queue' in self.state:
                for rec in self.state['link_queue']:
                    job = DownloadJob.from_json(rec)
                    self.link_queue.put(job)
                logger.info('Link queue resumed, entries: %d' % len(self.state['link_queue']))

        except Exception as e:
            traceback.print_exc()
            logger.warning('Exception in resuming the state %s' % e)
            logger.error('State resume failed, exiting')
            sys.exit(1)


def main():
    args_src = sys.argv
    parser = argparse.ArgumentParser(description='Downloads GitHub SSH keys')
    parser.add_argument('-c', dest='config', default=None, help='JSON config file')
    parser.add_argument('-s', dest='status', default=None, help='JSON status file')
    parser.add_argument('-t', dest='threads', default=1, help='Number of download threads to use')

    args = parser.parse_args(args=args_src[1:])
    config_file = args.config

    audit_file = os.path.join(os.getcwd(), 'audit.json')
    state_file = args.status if args.status is not None else os.path.join(os.getcwd(), 'state.json')
    if os.path.exists(state_file):
        utils.file_backup(state_file, backup_dir='.')

    sys.argv = [args_src[0]]
    l = GitHubLoader(state_file=state_file, config_file=config_file, audit_file=audit_file, threads=args.threads)
    l.work()
    sys.argv = args_src


# Launcher
if __name__ == "__main__":
    main()


