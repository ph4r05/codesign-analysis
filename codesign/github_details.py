#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
GitHub key downloader.
We use this for academic research on SSH keys entropy.
"""

import os
import sys
import inspect
import resource

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
from evt_dequeue import EvtDequeue

from github_base import AccessResource, RateLimitHit

from database import GitHubKey, GitHubUser as GitHubUserDb
from database import GitHubUserDetails, GitHubUserOrgs, GitHubRepo
from database import Base as DB_Base

from sqlalchemy.orm import scoped_session
import sqlalchemy as salch

import gc
import mem_top
from pympler.tracker import SummaryTracker
from collections import OrderedDict, namedtuple
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

logger = logging.getLogger(__name__)
coloredlogs.install(level=logging.DEBUG)


class DownloadJob(object):
    """
    Represents link to download
    """

    TYPE_USER = 1
    TYPE_ORG = 2
    TYPE_REPOS_USER = 3
    TYPE_REPOS_ORG = 4

    __slots__ = ['url', 'type', 'user', 'meta', 'fail_cnt', 'last_fail', 'priority', 'time_added']

    def __init__(self, url=None, jtype=TYPE_USER, user=None, priority=0, time_added=None, meta=None, *args, **kwargs):
        self.url = url
        self.type = jtype
        self.user = user
        self.meta = meta
        self.fail_cnt = 0
        self.last_fail = 0
        self.priority = priority
        self.time_added = time.time() if time_added is None else time_added

    def to_json(self):
        js = collections.OrderedDict()
        js['url'] = self.url
        js['type'] = self.type
        js['fail_cnt'] = self.fail_cnt
        js['last_fail'] = self.last_fail
        js['priority'] = self.priority
        js['time_added'] = self.time_added
        js['meta'] = self.meta
        if self.user is not None:
            js['user_id'] = self.user.user_id
            js['user_name'] = self.user.user_name
            js['user_type'] = self.user.user_type
            js['user_url'] = self.user.user_url
        return js

    @classmethod
    def from_json(cls, js):
        tj = cls()
        tj.url = js['url']
        tj.type = js['type']
        tj.fail_cnt = js['fail_cnt']
        tj.last_fail = js['last_fail']
        tj.priority = utils.defvalkey(js, 'priority', 0)
        tj.time_added = utils.defvalkey(js, 'time_added', 0)
        tj.meta = utils.defvalkey(js, 'meta', None)
        if 'user_id' in js:
            user_url = js['user_url'] if 'user_url' in js else None
            # tj.user = GitHubUser(user_id=js['user_id'], user_name=js['user_name'], user_type=js['user_type'], user_url=user_url)
        return tj

    @staticmethod
    def cmp(self, other):
        """
        Comparator
        :param self:
        :param other:
        :return:
        """
        # Inside the category: fail cnt, time added.
        if self.type == other.type:
            if self.fail_cnt == other.fail_cnt:
                if self.time_added == other.time_added:
                    return int(other.priority - self.priority)
                else:
                    return int(self.time_added - other.time_added)
            else:
                return int(self.fail_cnt - other.fail_cnt)
        else:
            # Outside the category - priority ordering. Higher the priority, sooner will be picked
            if self.priority == other.priority:
                return int(self.time_added - other.time_added)
            else:
                return int(other.priority - self.priority)

    def __cmp__(self, other):
        """
        Compare operation for priority queue.
        :param other:
        :return:
        """
        return self.cmp(self, other)


class GitHubLoader(Cmd):
    """
    GitHub SSH keys loader
    """
    prompt = '$> '

    LINK_FACTOR = 70
    USERS_URL = 'https://api.github.com/users?since=%s'
    KEYS_URL = 'https://api.github.com/users/%s/keys'

    USER_DETAIL_URL = 'https://api.github.com/users/%s'
    USER_REPOS_URL = 'https://api.github.com/users/%s/repos'
    USER_ORGS_URL = 'https://api.github.com/users/%s/orgs'
    ORG_REPOS_URL = 'https://api.github.com/orgs/%s/repos'

    def __init__(self, attempts=5, threads=1, state=None, state_file=None, config_file=None, audit_file=None,
                 max_mem=None, *args, **kwargs):

        Cmd.__init__(self, *args, **kwargs)
        self.t = Terminal()

        self.args = None
        self.attempts = int(attempts)
        self.total = None
        self.terminate = False

        self.last_users_count = None
        self.user_lock = Lock()
        self.processed_user_set = set()
        self.processed_user_set_lock = Lock()
        self.orgs_loaded_set = set()
        self.orgs_loaded_lock = Lock()

        self.max_mem = max_mem
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
        self.link_queue = Queue.PriorityQueue()  # Store links to download here
        self.worker_threads = []

        self.state_thread = None
        self.state_thread_lock = Lock()

        self.resources_list = []
        self.resources_queue = Queue.PriorityQueue()
        self.local_data = threading.local()

        self.new_users_events = EvtDequeue()
        self.new_keys_events = EvtDequeue()

        self.db_config = None
        self.engine = None
        self.session = None

        self.mem_tracker = None

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

    def trigger_quit(self):
        """
        Terminal condition & file change
        :return:
        """
        self.trigger_stop()
        utils.try_touch('.github-quit')

    def do_quit(self, arg):
        self.trigger_quit()
        logger.info('Waiting for thread termination')

        time.sleep(1)
        logger.info('Quitting')
        return Cmd.do_quit(self, arg)

    def do_reset(self, line):
        print('\033c')

    def do_gc(self, line):
        gc.collect()

    def do_mem_top(self, line):
        print(mem_top.mem_top())

    def do_mem_track_init(self, line):
        self.mem_tracker = SummaryTracker()

    def do_mem_track_diff(self, line):
        print(self.mem_tracker.print_diff())

    def do_mem_track_deinit(self, line):
        self.mem_tracker = None

    def do_mem(self, line):
        print('Memory usage: %s kB' % resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)

    def do_state(self, line):
        js = self.state_gen()

        if line is None or len(line) == 0:
            del js['link_queue']
            del js['resource_stats']
        elif line == '1':
            del js['link_queue']

        print(json.dumps(js, indent=2, cls=utils.AutoJSONEncoder))

    def do_deq_enable(self, line):
        self.new_keys_events.disabled = False
        self.new_users_events.disabled = False

    def do_deq_disable(self, line):
        self.new_keys_events.disabled = True
        self.new_users_events.disabled = True

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

            # Process resources - randomized
            if 'res' in self.config:
                res_tmp = self.config['res']
                random.shuffle(res_tmp)
                for idx, res in enumerate(res_tmp):
                    r = AccessResource(usr=res['usr'], token=res['token'], idx=idx)
                    self.resources_list.append(r)
                    self.resources_queue.put(r)
                    logger.info('Resource %02d loaded: %s' % (idx, r.usr))
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

    def cli(self):
        """
        CLI thread
        :return:
        """
        logger.info('CLI thread started')
        self.cmdloop()
        logger.info('Terminating CLI thread')

    def _init_queue(self):
        """
        Initializes link queue
        :return: 
        """
        sess = self.session()
        logger.debug('Loading users...')

        users_cnt = 0
        all_keys = sess.query(GitHubKey).filter(GitHubKey.is_interesting == 1).all()
        logger.debug('All users loaded')

        for rec in all_keys:
            users_cnt += 1

            job = DownloadJob(url=self.USER_DETAIL_URL % rec.key_user_found, jtype=DownloadJob.TYPE_USER,
                              meta={'user': rec.key_user_found, 'user_id': rec.key_user_id_found})
            self.link_queue.put(job)

            job = DownloadJob(url=self.USER_ORGS_URL % rec.key_user_found, jtype=DownloadJob.TYPE_ORG,
                              meta={'user': rec.key_user_found, 'user_id': rec.key_user_id_found})
            self.link_queue.put(job)

            job = DownloadJob(url=self.USER_REPOS_URL % rec.key_user_found, jtype=DownloadJob.TYPE_REPOS_USER,
                              meta={'user': rec.key_user_found, 'user_id': rec.key_user_id_found})
            self.link_queue.put(job)

        logger.info('Queue initialized, users cnt: %s' % users_cnt)
        utils.silent_close(sess)

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
            self._init_queue()

        # Worker threads
        self.init_workers()

        logger.info('Main thread started %s %s %s' % (os.getpid(), os.getppid(), threading.current_thread()))

        # CLI thread
        cli_thread = threading.Thread(target=self.cli, args=())
        cli_thread.setDaemon(True)
        cli_thread.start()

        # Join on workers
        self.after_loop()
        logger.info('Terminating main thread')
        return None

    def after_loop(self, wait_for_state=True):
        """
        After work loop finishes
        :return:
        """
        logger.info('Waiting termination of slave threads')

        # Wait here for termination of all workers and monitors.
        try:
            for t in self.worker_threads:
                t.join()

            if wait_for_state:
                self.state_thread.join()
        except:
            logger.error('Exception during thread join')
            logger.error(traceback.format_exc())

        logger.info('All threads terminates, last state save')
        self.state_save()

    #
    # General link processing & queue management
    #

    def work_thread_main(self, idx):
        """
        Worker thread main loop
        :return:
        """
        self.local_data.idx = idx
        logger.info('Working thread %d started' % idx)

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

            except RateLimitHit as e:
                logger.error('[%d] Rate limit hit: %s, failcnt: %d, res: %s, exception: %s'
                             % (idx, job.url, job.fail_cnt, resource.usr, e))
                continue

            except Exception as e:
                logger.error('[%d] Exception in processing job: %s, failcnt: %d, res: %s, exception: %s'
                             % (idx, job.url, job.fail_cnt, resource.usr, e))

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
                    self.audit_log('404', job.url, jtype=job.type, job=job)
                    self.flush_audit()
                    continue

                self.process_downloaded(job, js_data, headers, raw_response)

            except Exception as e:
                logger.error('[%d] Unexpected exception, processing type %s, link %s: cnt: %d, res: %s, %s'
                             % (idx, job.type, job.url, job.fail_cnt, resource.usr, e))

                traceback.print_exc()
                self.on_job_failed(job)
            finally:
                self.local_data.resource = None
                self.local_data.job = None
                self.local_data.last_usr = None
                self.local_data.last_remaining = None
                resource = None
                job = None
                headers = None
                raw_response = None

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
        if job.fail_cnt > 35:
            logger.warning('Job failed too many times %s' % job.url)
            self.audit_log('too-many-fails', job.url, jtype=job.type, job=job)
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
        resource.last_used = time.time()
        resource.used_cnt += 1

        if res.status_code == 403 and resource.remaining < 10:
            resource.fail_cnt += 1
            raise RateLimitHit

        if res.status_code == 404:
            resource.fail_cnt += 1
            logger.warning('URL not found: %s' % job.url)
            return None, None, None

        if res.status_code // 100 != 2:
            resource.fail_cnt += 1
            res.raise_for_status()

        data = res.content
        if data is None:
            resource.fail_cnt += 1
            raise Exception('Empty response')

        js = json.loads(data, object_pairs_hook=OrderedDict)
        return js, headers, res

    #
    # Crawl specific methods
    #

    def process_downloaded(self, job, js_data, headers, raw_response):
        """
        Process downloaded page
        :param self: 
        :param job: 
        :param js_data: 
        :param headers: 
        :param raw_response: 
        :return: 
        """
        if job.type == DownloadJob.TYPE_USER:
            self.process_user(job, js_data, headers, raw_response)
        elif job.type == DownloadJob.TYPE_ORG:
            self.process_org(job, js_data, headers, raw_response)
        elif job.type == DownloadJob.TYPE_REPOS_USER:
            self.process_repo(job, js_data, headers, raw_response, True)
        elif job.type == DownloadJob.TYPE_REPOS_ORG:
            self.process_repo(job, js_data, headers, raw_response, False)
        else:
            logger.error('Unrecognized type %s' % job.type)

    def process_user(self, job, js, headers, raw_response):
        """
        Process user detail data
        :param job:
        :param js:
        :param headers:
        :param raw_response:
        :return:
        """
        if 'id' not in js:
            logger.error('Field ID not found in user')
            return

        s = self.session()
        try:
            user_id = int(js['id'])
            dbu = s.query(GitHubUserDetails).filter(GitHubUserDetails.id == user_id).one_or_none()
            is_new = False

            if dbu is None:
                is_new = True
                dbu = GitHubUserDetails()
                dbu.id = user_id

            dbu.date_last_check = salch.func.now()
            dbu.username = js['login']
            dbu.name = utils.utf8ize(utils.defvalkey(js, 'name'))

            dbu.company = utils.utf8ize(utils.defvalkey(js, 'company'))
            dbu.blog = utils.defvalkey(js, 'blog')
            dbu.email = utils.defvalkey(js, 'email')
            dbu.bio = utils.utf8ize(utils.defvalkey(js, 'bio'))
            dbu.usr_type = utils.defvalkey(js, 'type')

            dbu.public_repos = js['public_repos']
            dbu.public_gists = js['public_gists']
            dbu.followers = js['followers']
            dbu.following = js['following']

            dbu.created_at = utils.dt_norm(utils.try_parse_timestamp(utils.defvalkey(js, 'created_at')))
            dbu.updated_at = utils.dt_norm(utils.try_parse_timestamp(utils.defvalkey(js, 'updated_at')))

            if is_new:
                s.add(dbu)
            else:
                s.merge(dbu)
            s.commit()
            s.flush()
            s.expunge_all()

        except Exception as e:
            logger.error('Exception storing user details: %s: %s' % (js['id'], e))
            logger.debug(traceback.format_exc())

        finally:
            utils.silent_close(s)

    def process_org(self, job, js, headers, raw_response):
        """
        Process user -> orgs data
        :param job:
        :param js:
        :param headers:
        :param raw_response:
        :return:
        """
        new_orgs = []
        for org in js:
            if 'id' not in org:
                logger.error('Field ID not found in orgs')
                continue

            s = self.session()
            try:
                org_id = int(org['id'])

                # delete first - avoid excs
                s.query(GitHubUserOrgs)\
                    .filter(GitHubUserOrgs.org_id == org_id)\
                    .filter(GitHubUserOrgs.username == job.meta['user'])\
                    .delete()

                dbu = GitHubUserOrgs()
                dbu.username = job.meta['user']
                dbu.org_id = org['id']
                dbu.org_name = org['login']
                dbu.org_desc = utils.utf8ize(org['description'])
                new_orgs.append(org['login'])

                s.add(dbu)

                s.commit()
                s.flush()
                s.expunge_all()

            except Exception as e:
                logger.error('Exception storing user->org details: %s: %s' % (org['id'], e))
                logger.debug(traceback.format_exc())

            finally:
                utils.silent_close(s)

        if len(js) == 0:
            return

        # Load next page
        cur_page = utils.defvalkey(job.meta, 'page', 1)
        new_url = (self.USER_ORGS_URL % job.meta['user']) + ('?page=%s' % (cur_page + 1))
        new_meta = dict(job.meta)
        new_meta['page'] = cur_page + 1

        job = DownloadJob(url=new_url, jtype=DownloadJob.TYPE_ORG, meta=new_meta)
        self.link_queue.put(job)

        # Load repositories for new organisations
        not_loaded_orgs = None
        with self.orgs_loaded_lock:
            new_orgs_set = set(new_orgs)
            not_loaded_orgs = new_orgs_set - self.orgs_loaded_set
            for x in new_orgs:
                self.orgs_loaded_set.add(x)

        for x in not_loaded_orgs:
            job = DownloadJob(url=self.ORG_REPOS_URL % x, jtype=DownloadJob.TYPE_REPOS_ORG, meta={'org': x})
            self.link_queue.put(job)

    def process_repo(self, job, js, headers, raw_response, from_user):
        """
        Process repo list page
        :param job: 
        :param js: 
        :param headers: 
        :param raw_response: 
        :param from_user: 
        :return: 
        """
        for repo in js:
            if 'id' not in repo:
                logger.error('Field ID not found in repos')
                continue

            s = self.session()
            try:
                repo_id = int(repo['id'])

                dbu = GitHubRepo()
                dbu.id = repo_id
                dbu.user_repo = from_user
                if from_user:
                    dbu.username = job.meta['user']
                else:
                    dbu.org_name = job.meta['org']

                if 'owner' in repo:
                    dbu.owner_id = repo['owner']['id']
                    dbu.owner_login = repo['owner']['login']

                dbu.repo_name = repo['full_name']
                dbu.repo_stars = repo['stargazers_count']
                dbu.repo_forks = repo['forks']
                dbu.repo_watchers = repo['watchers']
                dbu.repo_is_fork = repo['fork']
                dbu.repo_description = utils.utf8ize(repo['description'])

                dbu.repo_stargazers_url = repo['stargazers_url']
                dbu.repo_forks_url = repo['forks_url']

                s.add(dbu)
                s.commit()
                s.flush()
                s.expunge_all()

            except Exception as e:
                logger.error('Exception storing repo details: %s:%s meta: %s, url: %s, exc: %s'
                             % (repo['id'], repo['full_name'], json.dumps(job.meta), job.url, e))
                logger.debug(traceback.format_exc())

            finally:
                utils.silent_close(s)

        if len(js) == 0:
            return

        # Load next page
        cur_page = utils.defvalkey(job.meta, 'page', 1)
        new_meta = dict(job.meta)
        new_meta['page'] = cur_page + 1

        if from_user:
            new_url = (self.USER_REPOS_URL % job.meta['user']) + ('?page=%s' % (cur_page + 1))
            job = DownloadJob(url=new_url, jtype=DownloadJob.TYPE_REPOS_USER, meta=new_meta)
        else:
            new_url = (self.ORG_REPOS_URL % job.meta['org']) + ('?page=%s' % (cur_page + 1))
            job = DownloadJob(url=new_url, jtype=DownloadJob.TYPE_REPOS_ORG, meta=new_meta)

        self.link_queue.put(job)

    #
    # Resource management
    #

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

                logger.info('Rate limit exceeded on resource %s, remaining: %d, sleeping till: %d, it is %d seconds, '
                            '%d minutes'
                            % (resource.usr, resource.remaining, resource.reset_time, sleep_sec, sleep_sec / 60.0))
                self.sleep_interruptible(time.time() + sleep_sec)
                logger.info('Resource sleep finished %s' % resource.usr)

                # Reset estimations, needs to be refreshed
                resource.remaining = None
                resource.reset_time = None

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
        Interruptible sleep - sleep until given time.
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

    #
    # State
    #

    def flush_state(self):
        """
        Flushes state/config to the state file
        :return:
        """
        self.state['rate_limit_remaining'] = self.rate_limit_remaining
        self.state['rate_limit_reset'] = self.rate_limit_reset
        utils.flush_json(self.state, self.state_file_path)

    #
    # Auditing - errors, problems for further analysis
    #

    def audit_log(self, evt=None, link=None, jtype=None, job=None):
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

        if job is not None and isinstance(job, DownloadJob):
            log['job'] = job.to_json()

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
                    fa.write(json.dumps(x, cls=utils.AutoJSONEncoder) + "\n")
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
                # Dump stats each x seconds
                # Sleep is here because of dumping the state for the last time just before program quits.
                self.interruptible_sleep_delta(2)
                self.state_save()

                # Check memory conditions
                self.state_ram_check()

        except Exception as e:
            traceback.print_exc()
            logger.error('Exception in state: %s' % e)

        finally:
            pass

        logger.info('State loop terminated')

    def state_ram_check(self):
        """
        Checks memory terminating conditions
        :return:
        """

        if self.max_mem is None:
            return

        cur_ram = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        if cur_ram <= self.max_mem:
            return

        logger.warning('Maximum memory threshold reached: %s kB = %s MB, threshold = %s kB'
                       % (cur_ram, cur_ram / 1024.0, self.max_mem))
        self.trigger_stop()

    def state_gen(self):
        """
        Dumps state
        :return:
        """
        def link_char(job):
            if job.type == DownloadJob.TYPE_USER:
                return 'U'
            elif job.type == DownloadJob.TYPE_ORG:
                return 'o'
            elif job.type == DownloadJob.TYPE_REPOS_USER:
                return '.'
            elif job.type == DownloadJob.TYPE_REPOS_ORG:
                return ','
            else:
                return '!'

        try:
            js_q = collections.OrderedDict()
            js_q['gen'] = time.time()
            js_q['link_size'] = self.link_queue.qsize()
            js_q['memory'] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss

            # Dequeues
            self.new_users_events.maintain()
            self.new_keys_events.maintain()

            users_in_5min = self.new_users_events.under_limit(5*60)
            keys_in_5min = self.new_keys_events.under_limit(5*60)

            js_q['users_dequeue_size'] = self.new_users_events.len()
            js_q['keys_dequeue_size'] = self.new_keys_events.len()
            js_q['users_5min'] = users_in_5min
            js_q['keys_5min'] = keys_in_5min
            js_q['users_1min'] = users_in_5min / 5.0
            js_q['keys_1min'] = keys_in_5min / 5.0

            # link queue structure
            qdata = list(self.link_queue.queue)
            qdata.sort(cmp=DownloadJob.cmp)
            js_q['link_structure'] = ''.join([link_char(x) for x in qdata])

            # Stats.
            js_q['resource_stats'] = [x.to_json() for x in list(self.resources_list)]

            # Finally - the queue
            js_q['link_queue'] = [x.to_json() for x in qdata]
            return js_q

        except Exception as e:
            traceback.print_exc()
            logger.error('Exception in state: %s', e)

    def state_save(self):
        """
        saves the state
        :return:
        """
        try:
            js_q = self.state_gen()
            utils.flush_json(js_q, self.state_file_path)

        except Exception as e:
            traceback.print_exc()
            logger.error('Exception in state: %s', e)

    def state_resume(self):
        """
        Attempts to resume the queues from the monitoring files
        :return:
        """
        try:
            if self.state is None:
                return

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

    def main(self):
        """
        Main entry point
        :return: 
        """
        args_src = sys.argv
        parser = argparse.ArgumentParser(description='Downloads GitHub User info')
        parser.add_argument('-c', dest='config', default=None, help='JSON config file')
        parser.add_argument('-s', dest='status', default=None, help='JSON status file')
        parser.add_argument('-t', dest='threads', default=1, type=int, help='Number of download threads to use')
        parser.add_argument('--max-mem', dest='max_mem', default=None, type=int,
                            help='Maximal memory threshold in kB when program terminates itself')

        args = self.args = parser.parse_args(args=args_src[1:])

        self.threads = args.threads
        self.max_mem = args.max_mem

        self.config_file = args.config
        self.audit_file = os.path.join(os.getcwd(), 'audit.json')
        self.state_file_path = args.status if args.status is not None else os.path.join(os.getcwd(), 'state.json')

        if os.path.exists(self.state_file_path):
            utils.file_backup(self.state_file_path, backup_dir='.')

        if os.path.exists('.github-quit'):
            os.remove('.github-quit')

        sys.argv = [args_src[0]]
        logger.info('GitHub loader started, args: %s' % args)

        self.work()
        sys.argv = args_src


def main():
    l = GitHubLoader()
    l.main()


# Launcher
if __name__ == "__main__":
    main()


