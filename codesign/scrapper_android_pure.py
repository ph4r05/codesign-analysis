#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# http://sangaline.com/post/advanced-web-scraping-tutorial/
#

import os
import sys
import inspect
import resource
import base64

from requests.auth import HTTPBasicAuth

currentdir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
parentdir = os.path.dirname(currentdir)
sys.path.insert(0, parentdir)

import datetime
import hashlib
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
from database import GitHubKey, GitHubUser as GitHubUserDb, GitHubUserKeys, AndroidApkPureApp, AndroidApkPureApk
from database import Base as DB_Base
from sqlalchemy.orm import scoped_session
import sqlalchemy as salch
from trace_logger import Tracelogger

from lxml import html
from collections import OrderedDict
from apk_parse.apk import APK
from sec_light import BigNose

import gc
import mem_top
from pympler.tracker import SummaryTracker
from collections import OrderedDict, namedtuple
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.dsa import DSAPublicKey
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey

logger = logging.getLogger(__name__)
coloredlogs.install(level=logging.DEBUG)


class SkipException(Exception):
    def __init__(self, *args):
        super(SkipException, self).__init__(*args)


class TryAgainException(Exception):
    def __init__(self, *args):
        super(TryAgainException, self).__init__(*args)


class AndroidApp(object):
    """
    Android App model
    """
    def __init__(self, id=None, data=None):
        self.id = id
        self.data = data if data is not None else collections.OrderedDict()

    def to_json(self):
        js = collections.OrderedDict()
        js['id'] = self.id
        js['data'] = self.data
        return js

    @classmethod
    def from_json(cls, js):
        tj = cls()
        tj.id = js['id']
        tj.data = js['data']
        return tj


class DownloadJob(object):
    """
    Represents link to download
    """

    TYPE_SITEMAP = 1
    TYPE_DOWNLOAD = 3
    TYPE_APK = 4

    __slots__ = ['url', 'type', 'app', 'fail_cnt', 'last_fail', 'priority', 'time_added']

    def __init__(self, url=None, jtype=TYPE_SITEMAP, app=None, priority=0, time_added=None, *args, **kwargs):
        self.url = url
        self.type = jtype
        self.app = app
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
        if self.app is not None:
            js['app'] = self.app.to_json()
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
        if 'app' in js:
            tj.app = AndroidApp.from_json(js['app'])
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

    BASE_URL = 'https://apkpure.com'
    SITEMAP_URL = 'https://apkpure.com/sitemap.xml'

    def __init__(self, attempts=5, threads=1, state=None, state_file=None, config_file=None, audit_file=None,
                 max_mem=None, merge=False, num_res=1, cmd_args=None, *args, **kwargs):

        Cmd.__init__(self, *args, **kwargs)
        self.t = Terminal()
        self.trace_logger = Tracelogger(logger=logger)
        self.big_nose = BigNose()

        self.args = cmd_args
        self.apk_dir = self.args.apk_dir

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

        self.new_apps_events = EvtDequeue()
        self.new_apks_events = EvtDequeue()

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

        print(json.dumps(js, indent=2, cls=utils.AutoJSONEncoder))

    def do_deq_enable(self, line):
        self.new_apks_events.disabled = False
        self.new_apps_events.disabled = False

    def do_deq_disable(self, line):
        self.new_apks_events.disabled = True
        self.new_apps_events.disabled = True

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
        except Exception as e:
            logger.error('Exception during thread join')
            self.trace_logger.log(e)

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
                self.local_data.s = None
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

                self.local_data.s = self.session()

                if job.type == DownloadJob.TYPE_SITEMAP:
                    self.process_page_data(job, ret_data, headers, raw_response)
                elif job.type == DownloadJob.TYPE_DOWNLOAD:
                    self.process_download_data(job, ret_data, headers, raw_response)
                elif job.type == DownloadJob.TYPE_APK:
                    self.process_apk_data(job, ret_data, headers, raw_response)
                else:
                    raise Exception('Unknown job type: ' + job.type)

            except SkipException as ae:
                pass

            except TryAgainException as te:

                job.fail_cnt += 1
                job.last_fail = time.time()
                if job.fail_cnt > 35:
                    logger.warning('Job failed too many times %s' % job.url)
                    self.audit_log('too-many-fails', job.url, jtype=job.type, job=job)
                    self.flush_audit()
                else:
                    self.link_queue.put(job)  # re-insert to the queue for later processing

            except Exception as e:
                logger.error('[%d] Unexpected exception, processing type %s, link %s: cnt: %d, res: %s, %s'
                             % (idx, job.type, job.url, job.fail_cnt, resource.usr, e))

                self.trace_logger.log(e)
                self.on_job_failed(job)

            finally:
                utils.silent_close(self.local_data.s)
                self.local_data.s = None
                self.local_data.resource = None
                self.local_data.job = None
                self.local_data.last_usr = None
                self.local_data.last_remaining = None
                resource = None
                job = None
                headers = None
                raw_response = None

            self.interruptible_sleep_delta(2)

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
        if job.fail_cnt > 35 or (job.type == DownloadJob.TYPE_APK and job.fail_cnt > 7):
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
        data = None

        # Streamed downloading of the APK to the file
        res = None
        if job.type == DownloadJob.TYPE_APK:
            data = collections.OrderedDict()

            res = requests.get(job.url, stream=True, timeout=25)
            nurl = res.url

            fname = None
            try:
                fname = job.app.data['try_file_name']
            except:
                pass

            # fname = utils.slugify(nurl[ nurl.rfind('/') : ], repl=True)
            # fname = utils.safe_filename(re.findall("filename=(.+)", res.headers['content-disposition']))
            if fname is None or len(fname) == 0:
                fname = os.tempnam(self.apk_dir, 'apktmp')
            else:
                fname = os.path.join(self.apk_dir, fname)

            sha1 = hashlib.sha1()
            sha256 = hashlib.sha256()
            md5 = hashlib.md5()
            with open(fname, 'wb') as f:
                for chunk in res.iter_content(chunk_size=4096):
                    if chunk:
                        f.write(chunk)
                        sha1.update(chunk)
                        sha256.update(chunk)
                        md5.update(chunk)
                f.flush()

            size = os.path.getsize(fname)
            if size < 500:
                raise SkipException('File size too small: %s' % size)

            data['download_url'] = job.url
            data['fname'] = fname
            data['size'] = size
            data['sha1'] = sha1.hexdigest()
            data['sha256'] = sha256.hexdigest()
            data['md5'] = md5.hexdigest()

        else:
            res = requests.get(job.url, timeout=10, auth=auth)

        headers = res.headers
        resource.reset_time = float(headers.get('X-RateLimit-Reset', 0))
        resource.remaining = int(headers.get('X-RateLimit-Remaining', 1000))
        resource.last_used = time.time()
        resource.used_cnt += 1

        if res.status_code == 403 and resource.remaining < 10:
            resource.fail_cnt += 1
            raise RateLimitHit

        if res.status_code == 404 and job.type != DownloadJob.TYPE_SITEMAP:
            resource.fail_cnt += 1
            logger.warning('URL not found: %s' % job.url)
            return None, None, None

        if res.status_code // 100 != 2:
            resource.fail_cnt += 1
            res.raise_for_status()

        if job.type != DownloadJob.TYPE_APK:
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
        job = DownloadJob(url=self.SITEMAP_URL, jtype=DownloadJob.TYPE_SITEMAP)
        self.link_queue.put(job)
        logger.info('Kickoff link added: %s' % job.url)

    def link(self, x):
        """
        Creates an absolute link
        :param x:
        :return:
        """
        x = str(x)
        if x.startswith('http'):
            return x
        if not x.startswith('/'):
            x = '/%s' %x
        return self.BASE_URL % x

    def load_app(self, id_=None, title=None, package=None, processing_check=True, uploaded=None,
                 app_ver_type=None, pid=None, s=None):
        """
        Loads app by name
        :param id_:
        :param title:
        :param package:
        :param processing_check:
        :param uploaded:
        :param s:
        :return:
        """
        if s is None:
            s = self.local_data.s

        q = s.query(AndroidApkPureApp)

        if id_ is not None:
            q = q.filter(AndroidApkPureApp.id == id_)

        if title is not None:
            q = q.filter(AndroidApkPureApp.app_name == title)

        if package is not None:
            q = q.filter(AndroidApkPureApp.package_name == package)

        if app_ver_type is not None:
            q = q.filter(AndroidApkPureApp.version_type == app_ver_type)

        if processing_check:
            ct = datetime.datetime.utcnow() - datetime.timedelta(minutes=20)
            process_filter = salch.or_(
                AndroidApkPureApp.is_downloaded,
                AndroidApkPureApp.is_processed,
                AndroidApkPureApp.processing_started_at == None,
                AndroidApkPureApp.processing_started_at >= ct)

            if pid is not None:
                process_filter = salch.and_(AndroidApkPureApp.processing_pid == pid, process_filter)

            if uploaded:
                process_filter = salch.or_(AndroidApkPureApp.uploaded_at >= uploaded, process_filter)

            q = q.filter(process_filter)

        elif uploaded is not None:
            q = q.filter(AndroidApkPureApp.uploaded_at >= uploaded)

        return q.first()

    #
    # Processing page
    #

    def process_page_data(self, job, data, headers, raw_response):
        """
        Process app page listing
        :param job:
        :type job: DownloadJob
        :param data:
        :param headers:
        :param raw_response:
        :return:
        """
        cur_time = time.time()
        if '<?xml version' not in data:
            raise TryAgainException('Not a sitemap - reload')

        if 'sitemapindex' in data:
            self.process_sitemap_index(job, data, headers, raw_response)

        elif '<url>' in data:
            self.process_sitemap_sub(job, data, headers, raw_response)

        else:
            raise TryAgainException('Not a proper sub sitemap - reload')

    def process_sitemap_index(self, job, data, headers, raw_response):
        """
        Sitemap index - the main
        :param job:
        :param data:
        :param headers:
        :param raw_response:
        :return:
        """
        cur_time = time.time()
        tree = html.fromstring(data)
        locs = tree.xpath('//loc')

        for idx, loc in enumerate(locs):
            if self.args.test and idx >= 4:
                break

            url = utils.utf8ize(utils.first_non_empty(loc.xpath('text()')))
            if 'default.xml' in url:
                continue
            if 'topics.xml' in url:
                continue

            logger.debug(url)
            new_job = DownloadJob(url=self.link(url), jtype=DownloadJob.TYPE_SITEMAP, app=None,
                                  priority=1000, time_added=cur_time)
            self.link_queue.put(new_job)

    def process_sitemap_sub(self, job, data, headers, raw_response):
        """
        Sub sitemap - with data
        :param job:
        :param data:
        :param headers:
        :param raw_response:
        :return:
        """
        cur_time = time.time()
        pid = os.getpid()

        tree = html.fromstring(data)
        urls = tree.xpath('//url')
        for app_idx, url in enumerate(urls):
            try:
                loc = utils.first_non_empty(url.xpath('.//loc'))
                if loc is None:
                    logger.debug('No locs')
                    continue

                url_txt = utils.strip_trailing_slash(utils.utf8ize(utils.first_non_empty(loc.xpath('text()'))))
                package = url_txt[url_txt.rfind('/')+1:]
                relative_url = url_txt.replace('https://apkpure.com/', '')

                if relative_url.count('/') == 0:
                    logger.debug('Non apk link: %s' % relative_url)
                    continue

                last_mod = utils.first_non_empty(url.xpath('.//lastmod'))
                last_mod = utils.first_non_empty(last_mod.xpath('text()'))
                last_mod = utils.try_parse_datetime_string(last_mod)

                download_url = '%s/download?from=details' % url_txt

                app = self.load_app(package=package, processing_check=True, uploaded=last_mod, pid=pid)
                if app is not None:
                    logger.info('Already has %s' % package)
                    continue

                if self.args.test and app_idx > 1:  # and 'firefox' not in app_name.lower():
                    continue

                app_data = collections.OrderedDict()
                app_data['title'] = package
                app_data['package_name'] = package
                app_data['try_file_name'] = '%s.apk' % package
                app_data['pid'] = pid
                app_data['version'] = None
                app_data['uploaded'] = utils.unix_time(last_mod)
                app_data['size'] = None
                app_data['app_idx'] = app_idx
                app_data['referer'] = job.url
                app_data['downloads'] = None
                app_data['download_url'] = download_url
                logger.info(json.dumps(app_data, cls=utils.AutoJSONEncoder))

                s = self.local_data.s
                mapp = AndroidApkPureApp()
                mapp.app_name = package
                mapp.package_name = package
                mapp.url_detail = download_url
                mapp.uploaded_at = last_mod
                mapp.processing_pid = pid
                mapp.processing_started_at = salch.func.now()
                mapp.date_discovered = salch.func.now()
                mapp.date_last_check = salch.func.now()

                s.add(mapp)
                s.commit()

                app_data['model_id'] = mapp.id
                app = AndroidApp(data=app_data)

                new_job = DownloadJob(url=download_url, jtype=DownloadJob.TYPE_DOWNLOAD, app=app,
                                      priority=2000, time_added=cur_time)

                self.link_queue.put(new_job)

            except Exception as e:
                self.trace_logger.log(e)

    def process_download_data(self, job, data, headers, raw_response):
        """
        Process App download page - extract download URL
        :param job:
        :type job: DownloadJob
        :param data:
        :param headers:
        :param raw_response:
        :return:
        """
        cur_time = time.time()

        try:
            logger.debug('Download page downloaded')
            tree = html.fromstring(data)
            ahref_download = utils.first_non_empty(tree.xpath('//a[@id="download_link"]'))
            if ahref_download is None:
                logger.debug('Not downloadable: %s' % job.url)
                return

            apk_link = ahref_download.attrib['href']

            app = job.app
            app.data['url_apk'] = apk_link

            mapp = self.load_app(id_=app.data['model_id'])
            mapp.download_started_at = salch.func.now()

            self.local_data.s.merge(mapp)
            self.local_data.s.commit()

            new_job = DownloadJob(url=apk_link, jtype=DownloadJob.TYPE_APK, app=app, priority=5000, time_added=cur_time)
            self.link_queue.put(new_job)

        except Exception as e:
            self.trace_logger.log(e)
            raise SkipException('Download parse error')

    def process_apk_data(self, job, data, headers, raw_response):
        """
        Process downloaded APK file
        :param job:
        :type job: DownloadJob
        :param data:
        :param headers:
        :param raw_response:
        :return:
        """
        # process download APK file, open APK, read cert, fprint, store all thos info to DB
        logger.info('APK downloaded, len: %s' % data)

        app = job.app
        app_data = app.data
        app_data['apk'] = data

        self.process_apk(data['fname'], data)
        logger.info(json.dumps(app.data, indent=2, cls=utils.AutoJSONEncoder))

        mapp = self.load_app(id_=app.data['model_id'])
        mapp.is_downloaded = 1
        mapp.version_variant = utils.defvalkey(app_data, 'variant_title')
        mapp.downloaded_at = salch.func.now()
        self.local_data.s.merge(mapp)
        self.local_data.s.commit()

        apkdat = app_data['apk']

        mapk = AndroidApkPureApk()
        mapk.app = mapp
        mapk.app_id = mapp.id
        mapk.url_download = utils.utf8ize(app_data['download_url'])
        mapk.fpath = utils.defvalkey(apkdat, 'fname')
        mapk.date_discovered = salch.func.now()

        mapk.file_size = apkdat['size']
        mapk.md5 = apkdat['md5']
        mapk.sha1 = apkdat['sha1']
        mapk.sha256 = apkdat['sha256']

        mapk.is_xapk = utils.defvalkey(apkdat, 'is_xapk')
        mapk.sub_apk_size = utils.defvalkey(apkdat, 'sub_apk_size')
        mapk.apk_package = mapp.package_name
        mapk.apk_version_code = utils.defvalkey(apkdat, 'apk_version_code')
        mapk.apk_version_name = utils.defvalkey(apkdat, 'apk_version_name')
        mapk.apk_min_sdk = utils.defvalkey(apkdat, 'apk_min_sdk')
        mapk.apk_tgt_sdk = utils.defvalkey(apkdat, 'apk_tgt_sdk')
        mapk.apk_max_sdk = utils.defvalkey(apkdat, 'apk_max_sdk')

        mapk.sign_date = utils.defvalkey(apkdat, 'sign_date_dt')
        mapk.sign_info_cnt = utils.defvalkey(apkdat, 'sign_info_cnt')
        mapk.sign_serial = utils.defvalkey(apkdat, 'sign_serial')
        mapk.sign_issuer = utils.utf8ize(utils.defvalkey(apkdat, 'sign_issuer'))
        mapk.sign_alg = utils.defvalkey(apkdat, 'sign_alg')
        mapk.sign_raw = utils.defvalkey(apkdat, 'sign_raw')

        mapk.cert_alg = utils.defvalkey(apkdat, 'cert_alg')
        mapk.cert_fprint = utils.defvalkey(apkdat, 'cert_fprint')
        mapk.cert_not_before = utils.defvalkey(apkdat, 'cert_not_before_dt')
        mapk.cert_not_after = utils.defvalkey(apkdat, 'cert_not_after_dt')
        mapk.cert_dn = utils.utf8ize(utils.defvalkey(apkdat, 'cert_dn'))
        mapk.cert_issuer_dn = utils.utf8ize(utils.defvalkey(apkdat, 'cert_issuer_dn'))
        mapk.cert_raw = utils.defvalkey(apkdat, 'der')

        mapk.pub_type = utils.defvalkey(apkdat, 'pubkey_type')
        mapk.pub_modulus = utils.defvalkey(apkdat, 'modulus_hex')
        mapk.pub_exponent = utils.defvalkey(apkdat, 'cert_e_hex')
        mapk.pub_modulus_size = utils.defvalkey(apkdat, 'modulus_size')
        mapk.pub_interesting = utils.defvalkey(apkdat, 'smells_nice')
        self.local_data.s.add(mapk)
        self.local_data.s.commit()

        mapp.is_processed = 1
        mapp.processed_at = salch.func.now()
        self.local_data.s.merge(mapp)
        self.local_data.s.commit()

        try:
            if self.args.apk_done_dir != self.apk_dir:
                shutil.move(data['fname'], self.args.apk_done_dir)
            else:
                os.remove(data['fname'])
        except Exception as e:
            self.trace_logger.log(e)

    def process_apk(self, file_path, apk_rec):
        """
        Processing APK - extracting useful information, certificate.
        :param file_path:
        :param apk_rec:
        :return:
        """
        # Downloaded - now parse
        try:
            logger.debug('Parsing APK')

            # Optimized parsing - parse only manifest and certificate, no file type inference.
            # In case of xapks (nested apks), use temp dir to extract it.
            apkf = APK(file_path, process_now=False, process_file_types=False, as_file_name=True, temp_dir=self.apk_dir)

            # Save some time - do not re-compute MD5 inside apk parsing lib
            if 'md5' in apk_rec:
                apkf.file_md5 = apk_rec['md5']

            apkf.process()
            apk_rec['is_xapk'] = apkf.is_xapk
            apk_rec['sub_apk_size'] = apkf.sub_apk_size

            # Android related info (versions, SDKs)
            utils.extend_with_android_data(apk_rec, apkf, logger)
            pem = apkf.cert_pem

            x509 = utils.load_x509(pem)
            apk_rec['cert_alg'] = x509.signature_hash_algorithm.name

            pub = x509.public_key()
            if isinstance(pub, RSAPublicKey):
                apk_rec['pubkey_type'] = 'RSA'
                mod = pub.public_numbers().n

                apk_rec['modulus'] = mod
                apk_rec['modulus_hex'] = '%x' % mod
                apk_rec['modulus_size'] = len(bin(mod)) - 2
                apk_rec['cert_e'] = x509.public_key().public_numbers().e
                apk_rec['cert_e_hex'] = '%x' % apk_rec['cert_e']
                apk_rec['smells_nice'] = self.big_nose.smells_good(mod)

            elif isinstance(pub, DSAPublicKey):
                apk_rec['pubkey_type'] = 'DSA'

            elif isinstance(pub, EllipticCurvePublicKey):
                apk_rec['pubkey_type'] = 'ECC'

            else:
                apk_rec['pubkey_type'] = ''

            apk_rec['sign_raw'] = base64.b64encode(apkf.pkcs7_der)

            utils.extend_with_cert_data(apk_rec, x509, logger)
            utils.extend_with_pkcs7_data(apk_rec, apkf.pkcs7_der, logger)
            apk_rec['pem'] = pem
            apk_rec['der'] = base64.b64encode(apkf.cert_der)

        except Exception as e:
            self.trace_logger.log(e)
            logger.error('APK parsing failed: %s' % e)

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
            self.trace_logger.log(e)
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

    def link_type_char(self, x):
        """
        Link repr
        :param x:
        :return:
        """
        if x == DownloadJob.TYPE_SITEMAP:
            return 's'
        elif x == DownloadJob.TYPE_DOWNLOAD:
            return '-'
        elif x == DownloadJob.TYPE_APK:
            return '*'
        else:
            return ' '

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
            self.new_apps_events.maintain()
            self.new_apks_events.maintain()

            apps_in_5min = self.new_apps_events.under_limit(5 * 60)
            apks_in_5min = self.new_apks_events.under_limit(5 * 60)

            js_q['app_dequeue_size'] = self.new_apps_events.len()
            js_q['apk_dequeue_size'] = self.new_apks_events.len()
            js_q['apps_5min'] = apps_in_5min
            js_q['apks_5min'] = apks_in_5min
            js_q['apps_1min'] = apps_in_5min / 5.0
            js_q['apks_1min'] = apks_in_5min / 5.0

            # link queue structure
            qdata = list(self.link_queue.queue)
            qdata.sort(cmp=DownloadJob.cmp)
            js_q['link_structure'] = ''.join([self.link_type_char(x.type) for x in qdata])

            # Stats.
            js_q['resource_stats'] = [x.to_json() for x in list(self.resources_list)]

            # Finally - the queue
            js_q['link_queue'] = [x.to_json() for x in qdata]
            return js_q

        except Exception as e:
            self.trace_logger.log(e)
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
            self.trace_logger.log(e)
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
            self.trace_logger.log(e)
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
    parser.add_argument('--test', dest='test', default=False, action='store_const', const=True,
                        help='Just testing')
    parser.add_argument('--apk-dir', dest='apk_dir', default='.',
                        help='Dir to cache APKs')
    parser.add_argument('--apk-done-dir', dest='apk_done_dir', default='.',
                        help='Dir to move APKs after processing finished')

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
                         max_mem=args.max_mem, merge=args.merge, num_res=args.resnum, cmd_args=args)
    l.work()
    sys.argv = args_src


# Launcher
if __name__ == "__main__":
    main()
