#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# http://sangaline.com/post/advanced-web-scraping-tutorial/
#

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
import dbutil

from github_base import AccessResource, RateLimitHit
from database import GitHubKey, GitHubUser as GitHubUserDb, GitHubUserKeys
from database import Base as DB_Base
from sqlalchemy.orm import scoped_session
import sqlalchemy as salch
from trace_logger import Tracelogger

from lxml import html
from collections import OrderedDict
from apk_parse.apk import APK

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

    TYPE_PAGE = 1
    TYPE_DETAIL = 2
    TYPE_DOWNLOAD = 3
    TYPE_APK = 4

    __slots__ = ['url', 'type', 'user', 'fail_cnt', 'last_fail', 'priority', 'time_added']

    def __init__(self, url=None, jtype=TYPE_PAGE, user=None, priority=0, time_added=None, *args, **kwargs):
        self.url = url
        self.type = jtype
        self.user = user
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
        if 'user_id' in js:
            user_url = js['user_url'] if 'user_url' in js else None
            tj.user = None #GitHubUser(user_id=js['user_id'], user_name=js['user_name'], user_type=js['user_type'], user_url=user_url)
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


class AndroidApkLoader(Cmd):
    """
    Android APK crawler
    """
    prompt = '$> '

    LINK_FACTOR = 70
    PAGE_URL = 'https://www.apkmirror.com/page/%s/'

    def __init__(self, attempts=5, threads=1, state=None, state_file=None, config_file=None, audit_file=None,
                 max_mem=None, merge=False, num_res=1, *args, **kwargs):

        Cmd.__init__(self, *args, **kwargs)
        self.t = Terminal()
        self.trace_logger = Tracelogger(logger=logger)

        self.attempts = int(attempts)
        self.total = None
        self.terminate = False
        self.since_id = 1
        self.last_users_count = None
        self.user_lock = Lock()
        self.processed_user_set = set()
        self.processed_user_set_lock = Lock()

        self.max_mem = max_mem
        self.merge = merge

        self.users_per_page = 30
        self.users_bulk_load_pages = 500
        self.user_load_bulk = 5000
        self.user_refill_lock = Lock()
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
        self.num_res = num_res
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
        utils.try_touch('.android-quit')

    #
    # CMD handlers
    #

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

        print(json.dumps(js, indent=2))

    def do_deq_enable(self, line):
        self.new_keys_events.disabled = False
        self.new_users_events.disabled = False

    def do_deq_disable(self, line):
        self.new_keys_events.disabled = True
        self.new_users_events.disabled = True

    #
    # Init
    #

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

        for i in range(self.num_res):
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

    #
    # Operation
    #

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
            self.kickoff_links()

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
            ret_data = None
            try:
                self.local_data.job = job
                self.local_data.resource = resource
                ret_data, headers, raw_response = self.load_page_local()

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
                if ret_data is None:
                    self.audit_log('404', job.url, jtype=job.type, job=job)
                    self.flush_audit()
                    continue

                if job.type == DownloadJob.TYPE_PAGE:
                    self.process_page_data(job, ret_data, headers, raw_response)
                elif job.type == DownloadJob.TYPE_DETAIL:
                    self.process_detail_data(job, ret_data, headers, raw_response)
                elif job.type == DownloadJob.TYPE_DOWNLOAD:
                    self.process_download_data(job, ret_data, headers, raw_response)
                elif job.type == DownloadJob.TYPE_APK:
                    self.process_apk_data(job, ret_data, headers, raw_response)
                else:
                    raise Exception('Unknown job type: ' + job.type)

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

        # TODO: stream downloading of the APK to the file
        res = requests.get(job.url, timeout=10, auth=auth)
        headers = res.headers

        resource.reset_time = float(headers.get('X-RateLimit-Reset', 0))
        resource.remaining = int(headers.get('X-RateLimit-Remaining', 1000))
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

        return data, headers, res

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
    # Parser and processing logic
    #

    def kickoff_links(self):
        """
        Kick off the scrapping by adding initial links to the queue
        :return:
        """
        job = DownloadJob(url=self.PAGE_URL % self.since_id, jtype=DownloadJob.TYPE_PAGE)
        self.link_queue.put(job)
        logger.info('Kickoff link added: %s' % job.url)

    # def old_process(self, job, js, headers, raw_response):
    #     max_id = 0
    #     github_users = []
    #     cur_time = int(time.time())
    #     for user in js:
    #         if 'id' not in user:
    #             logger.error('Field ID not found in user')
    #             continue
    #
    #         github_user = GitHubUser(user_id=int(user['id']), user_name=user['login'],
    #                                  user_type=user['type'], user_url=user['url'])
    #         github_users.append(github_user)
    #
    #         if github_user.user_id > max_id:
    #             max_id = github_user.user_id
    #
    #         if self.users_only:
    #             continue
    #
    #         key_url = '%s/keys' % github_user.user_url
    #         new_job = DownloadJob(url=key_url, jtype=DownloadJob.TYPE_KEYS, user=github_user,
    #                               priority=random.randint(0, 1000), time_added=cur_time)
    #         self.link_queue.put(new_job)
    #
    #     # Link with the maximal user id
    #     users_url = self.USERS_URL % max_id
    #     new_job = DownloadJob(url=users_url, jtype=DownloadJob.TYPE_USERS, time_added=cur_time)
    #
    #     # Optimizing the position of this link in the link queue
    #     queue_size = self.link_queue.qsize()
    #     queue_size_max = self.LINK_FACTOR * self.threads
    #     fill_up_ratio = queue_size / float(queue_size_max)
    #
    #     # Key jobs are uniformly distributed on priorities 0...1000.
    #     # To increase queue size pick priority closer to 1000, do decrease, closer to 0
    #     priority = random.randint(0, 500)
    #     if queue_size < queue_size_max:
    #         priority = int((1 - fill_up_ratio) * 5000) + 500
    #     if queue_size > 3*queue_size_max:
    #         priority = 0
    #
    #     new_job.priority = priority
    #     lucky_one = False
    #     with self.user_lock:
    #         if self.since_id < max_id:
    #             self.since_id = max_id
    #             self.link_queue.put(new_job)
    #             lucky_one = True
    #
    #     logger.info('[%02d, usr=%20s, remaining=%5s] Processed users link %s, Next since: %3s. ResQSize: %4d, '
    #                 'LQSize: %4d, fill-up: %0.4f, priority: %4s, ram: %s kB, new=%s, New users: [%s]'
    #                 % (self.local_data.idx, self.local_data.last_usr, self.local_data.last_remaining,
    #                    len(github_users)+1, max_id, self.resources_queue.qsize(),
    #                    queue_size, fill_up_ratio, priority,
    #                    resource.getrusage(resource.RUSAGE_SELF).ru_maxrss, lucky_one,
    #                    ', '.join([str(x.user_name) for x in github_users])))
    #
    #     # Store all users.
    #     self.store_users_list(github_users)

    def process_page_data(self, job, data, headers, raw_response):
        """
        Process user data - produce keys links + next user link
        :param job:
        :param data:
        :param headers:
        :param raw_response:
        :return:
        """
        tree = html.fromstring(data)
        lists = tree.xpath('//div[@id="primary"]//div[@class="listWidget"]')
        for list_widget in lists:
            logger.debug('List widget: %s' % list_widget)
            eapp = list_widget.xpath('div[@class="appRow"]')

            if len(eapp) == 0:
                logger.warning('No results')
                return

            for eapp1 in eapp:
                try:
                    tbl_cel = eapp1[0][1][0]
                    ahref = tbl_cel[0][0]

                    link = ahref.attrib['href']
                    title = utils.first(ahref.xpath('text()'))

                    info_slide = eapp1.getnext()
                    version, uploaded, size, downloads = self.get_info_details(info_slide)
                    app_name = self.get_app_name(title, version)
                    app_ver_type = self.get_app_version_type(title, version)

                    logger.debug('Title / link [%s] [%s] ' % (title, link))
                    logger.debug('v: %s, upd: %s, size: %s, down: %s, appName: %s, verInfo: %s'
                                 % (version, uploaded, size, downloads, app_name, app_ver_type))

                    # TODO: download this app? already downloaded?

                except Exception as e:
                    self.trace_logger.log(e)

    def get_info_details(self, info_slide):
        """
        version, uploaded, size, downloads
        :param info_slide:
        :return:
        """
        version, uploaded, size, downloads = None, None, None, None

        try:
            version = utils.first(info_slide[0][1].xpath('text()'))
        except Exception as e:
            self.trace_logger.log(e)

        try:
            uploaded = utils.try_parse_timestamp(info_slide[1][1][0].attrib['data-utcdate'])
        except Exception as e:
            self.trace_logger.log(e)

        try:
            size = utils.first(info_slide[2][1].xpath('text()'))
            a, b = [x.strip() for x in re.sub(r'\s+', ' ', size).split(' ')]
            if b.lower() == 'mb':
                size = float(a) * 1024 * 1024
            elif b.lower() == 'kb':
                size = float(a) * 1024
            elif b.lower() == 'gb':
                size = float(a) * 1024 * 1024 * 1024
            else:
                size = None
        except Exception as e:
            self.trace_logger.log(e)

        try:
            downloads = int(utils.first(info_slide[3][1].xpath('text()')))
        except Exception as e:
            self.trace_logger.log(e)

        return version, uploaded, size, downloads

    def get_app_name(self, title, version):
        """
        Pure app name
        :param title:
        :param version:
        :return:
        """
        idx = title.find(version)
        if idx > 0:
            return utils.strip(title[0:idx])

        # fallback solution
        match = re.search(r'[0-9]+\b', title)
        if not match:
            return title
        start = match.start(0)
        if not start or start < 0:
            return title

        return utils.strip(title[0:start])

    def get_app_version_type(self, title, version):
        """
        Beta / alpha / test
        :param title:
        :param version:
        :return:
        """
        title = utils.lower(title)
        if re.search(r'\bbeta\b.*$', title):
            return 'beta'
        if re.search(r'\balpha\b.*$', title):
            return 'alpha'
        if re.search(r'\balfa\b.*$', title):
            return 'alpha'
        if re.search(r'\btest\b.*$', title):
            return 'alpha'
        if re.search(r'\brc\b.*$', title):
            return 'rc'
        if re.search(r'\bfree\b.*$', title):
            return 'free'
        if re.search(r'\bpro\b.*$', title):
            return 'pro'
        return None

    def store_users_list(self, users):
        """
        Stores all user in the list
        :param users
        :return:
        """
        # Handling gaps in the user space ID. With user-only optimization it causes
        # overlaps.
        reduced_by = 0
        with self.processed_user_set_lock:
            ids = [user.user_id for user in users]
            ids_ok = []
            for id in ids:
                if id in self.processed_user_set:
                    reduced_by += 1
                    continue
                self.processed_user_set.add(id)
                ids_ok.append(id)
            users = [user for user in users if user.user_id in ids_ok]

        # Bulk user load
        s = self.session()
        id_list = sorted([user.user_id for user in users])
        db_users = s.query(GitHubUserDb).filter(GitHubUserDb.id.in_(id_list)).all()
        db_user_map = {user.id: user for user in db_users}

        for user in users:
            self.new_users_events.insert()

            # Store user to the DB
            try:
                db_user = utils.defvalkey(db_user_map, key=user.user_id)
                self.store_user(user, s, db_user=db_user, db_user_loaded=True)

            except Exception as e:
                logger.warning('[%02d] Exception in storing user %s' % (self.local_data.idx, e))
                logger.warning(traceback.format_exc())
                logger.info('[%02d] idlist: %s' % (self.local_data.idx, id_list))
                self.trigger_quit()
                break

        try:
            s.commit()
            # logger.info('[%02d] Commited, reduced by: %s' % (self.local_data.idx, reduced_by))
        except Exception as e:
            logger.warning('[%02d] Exception in storing bulk users' % self.local_data.idx)
            logger.warning(traceback.format_exc())
            logger.info('[%02d] idlist: %s' % (self.local_data.idx, id_list))
            self.trigger_quit()
        finally:
            utils.silent_close(s)

    def process_detail_data(self, job, js, headers, raw_response):
        """
        Process user data - produce keys links + next user link
        :param job:
        :param js:
        :param headers:
        :param raw_response:
        :return:
        """
        # if variant page, pick one variant and download, if not, go to process_download_data

    def process_download_data(self, job, js, headers, raw_response):
        """
        Process user data - produce keys links + next user link
        :param job:
        :param js:
        :param headers:
        :param raw_response:
        :return:
        """
        # update with package name
        # update with version_number - 6.31.0 (631043)
        # generate directly download link: a, id=pbDropdown, data-postid contains ID

    def process_apk_data(self, job, js, headers, raw_response):
        """
        Processing key loaded data
        :param job:
        :param js:
        :param headers:
        :param raw_response:
        :return:
        """
        # process download APK file, open APK, read cert, fprint, store all thos info to DB

    def process_old_keys(self, job, js, headers, raw_response):
        """
        Processing key loaded data
        :param job:
        :param js:
        :param headers:
        :param raw_response:
        :return:
        """
        js_empty = js is None or len(js) == 0

        # Expect failures, commit everything before
        if self.merge and not js_empty:
            try:
                s = self.session()
                s.commit()
            except Exception as e:
                logger.warning('Could not pre-commit: %s' % e)

        # Store each key.
        for key in js:
            s = None
            self.new_keys_events.insert()

            try:
                s = self.session()
                self.store_key(job.user, key, s)
                s.commit()

                self.assoc_key(job.user.user_id, key['id'], s)
                s.commit()

                s.flush()        # writes changes to DB
                s.expunge_all()  # removes objects from session

            except Exception as e:
                logger.warning('Exception in storing key %s' % e)
                self.trace_logger.log(e)

            finally:
                utils.silent_close(s)
                s = None

    def store_user(self, user, s, db_user=None, db_user_loaded=False):
        """
        Stores username to the database.
        :param user:
        :return:
        """
        type_id = 0
        if user.user_type == 'User':
            type_id = 1
        elif user.user_type == 'Organization':
            type_id = 2

        try:
            if not db_user_loaded:
                db_user = s.query(GitHubUserDb).filter(GitHubUserDb.id == user.user_id).one_or_none()
            if db_user is not None:
                db_user.date_last_check = salch.func.now()
                db_user.usr_type = type_id
                s.merge(db_user)
                return 0

        except Exception as e:
            traceback.print_exc()
            logger.warning('User query problem: %s' % e)

        # Store a new user here
        try:
            db_user = GitHubUserDb()
            db_user.id = user.user_id
            db_user.username = user.user_name
            db_user.usr_type = type_id
            s.add(db_user)
            return 0

        except Exception as e:
            traceback.print_exc()
            logger.warning('[%02d] Exception during user store: %s' % (self.local_data.idx, e))
            if db_user_loaded:
                raise
            return 1

    def load_existing_key(self, key, s):
        """
        Loads existing key if exists
        :param key:
        :param s:
        :return:
        """
        key_id = int(key['id'])
        return s.query(GitHubKey).filter(GitHubKey.id == key_id).one_or_none()

    def store_key(self, user, key, s):
        """
        Stores user key to the database.
        :param user:
        :param key:
        :param s: current DB session
        :return:
        """

        # Loading phase
        existing_key = None
        try:
            if self.merge:
                existing_key = self.load_existing_key(key, s)

        except Exception as e:
            logger.warning('Exception: %s' % e)

        # Storing phase
        try:
            if existing_key is not None:
                existing_key.date_last_check = salch.func.now()
                s.merge(existing_key)
                return 0

            key_id = int(key['id'])
            key_raw = key['key']

            key_type, key_val = [utils.strip(x) for x in key_raw.split(' ', 1)]

            db_key = GitHubKey()
            db_key.id = key_id
            db_key.key_id = key_id
            db_key.key_type = key_type
            db_key.key_user_found = user.user_name
            db_key.key_user_id_found = user.user_id
            db_key.text_raw = key_raw

            if key_type == 'ssh-rsa':
                try:
                    key_obj = utils.load_ssh_pubkey(key_raw)
                    if isinstance(key_obj, RSAPublicKey):
                        db_key.key_size = key_obj.key_size
                        numbers = key_obj.public_numbers()
                        db_key.key_modulus_hex = '%x' % numbers.n
                        db_key.key_exponent = numbers.e
                except Exception as e:
                    logger.info('Exception during processing the key[%s]: %s' % (key_type, e))

            s.add(db_key)
            return 0

        except Exception as e:
            utils.silent_rollback(s)
            logger.warning('Exception during key store: %s' % e)
            return 1

    def assoc_key(self, user_id, key_id, s):
        """
        Association user <-> key
        :param user_id:
        :param key_id:
        :param s:
        :return:
        """
        try:
            uassoc = GitHubUserKeys()
            uassoc.user_id = user_id
            uassoc.key_id = key_id
            uassoc.fount_at = salch.func.now()
            uassoc.lost_at = None
            s.add(uassoc)
            return 0

        except Exception as e:
            utils.silent_rollback(s)
            logger.warning('Exception during key assoc: %s' % e)
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
        try:
            js_q = collections.OrderedDict()
            js_q['gen'] = time.time()
            js_q['link_size'] = self.link_queue.qsize()
            js_q['since_id'] = self.since_id
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
            js_q['link_structure'] = ''.join(['.' if x.type == DownloadJob.TYPE_PAGE else 'U' for x in qdata])

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
    parser = argparse.ArgumentParser(description='Downloads APKs')
    parser.add_argument('-c', dest='config', default=None,
                        help='JSON config file')
    parser.add_argument('-s', dest='status', default=None,
                        help='JSON status file')
    parser.add_argument('-t', dest='threads', default=1, type=int,
                        help='Number of download threads to use')
    parser.add_argument('--res', dest='resnum', default=1, type=int,
                        help='Number of active slots')
    parser.add_argument('--max-mem', dest='max_mem', default=None, type=int,
                        help='Maximal memory threshold in kB when program terminates itself')
    parser.add_argument('--merge', dest='merge', default=False, action='store_const', const=True,
                        help='Merge DB operation - merge instead of add. slower, updates if exists')

    args = parser.parse_args(args=args_src[1:])
    config_file = args.config

    audit_file = os.path.join(os.getcwd(), 'android-audit.json')
    state_file = args.status if args.status is not None else os.path.join(os.getcwd(), 'android-state.json')
    if os.path.exists(state_file):
        utils.file_backup(state_file, backup_dir='.')

    if os.path.exists('.android-quit'):
        os.remove('.android-quit')

    sys.argv = [args_src[0]]
    logger.info('Android loader started, args: %s' % args)
    l = AndroidApkLoader(state_file=state_file, config_file=config_file, audit_file=audit_file, threads=args.threads,
                         max_mem=args.max_mem, merge=args.merge, num_res=args.resnum)
    l.work()
    sys.argv = args_src


# Launcher
if __name__ == "__main__":
    main()





# Download details page
# detail_url = self.BASE_URL + link
# apk_rec['url_detail'] = detail_url
# logger.info('Downloading detail info: %s' % detail_url)
# tree = self.load_page(detail_url)

# # Sometimes there are more APKs matching
# ahref = tree.xpath('//div[@class="table-cell rowheight addseparator expand pad dowrap"]/a')
# if len(ahref) > 0:
#     ahref = ahref[0]
#     link = ahref.attrib['href']
#     title = ahref.xpath('text()')
#     logger.info('Title: %s, link: %s' % (title, link))
#
#     # Download particular APK page
#     detail_url = self.BASE_URL + link
#     apk_rec['url_detail2'] = detail_url
#     logger.info('Downloading APK detail info: %s' % detail_url)
#     tree = self.load_page(detail_url)
#
# ahref = tree.xpath('//a[@class="btn btn-flat downloadButton"]')[0]
# link = ahref.attrib['href']
# logger.info('Download link: %s' % link)
# # TODO: fetch more info about the APK
#
# # Fetch page with direct link
# download_url = self.BASE_URL + link
# apk_rec['url_download'] = download_url
# logger.info('Downloading APK download info: %s' % download_url)
# tree = self.load_page(download_url)
#
# ahref = tree.xpath('//div[@class="noPadding col-md-6 col-sm-6 col-xs-12"]/p/a')[0]
# link = ahref.attrib['href']
# logger.info('Direct link: %s' % link)


# item = ArtifactItem()
# item['url'] = response.url
# item['versions'] = versions
# item['misc_files'] = misc_files
# item['artifact_detected'] = is_artifact
# item['confidence'] = art_conf
# yield item
# yield Request(pom_link, callback=self.parse_pom, meta=dict(meta))


