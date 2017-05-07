#!/usr/bin/env python
# -*- coding: utf-8 -*-

import scrapy
import re
import os
import json
import argparse
import logging
import coloredlogs
from urlparse import urlparse
import traceback
import datetime
import scrapy
import utils
import versions as vv
import databaseutils
from collections import OrderedDict
from database import MavenArtifact, MavenSignature
from database import Base as DB_Base
from scrapper_tools import PomItem, AscItem, ArtifactItem

from scrapy.settings.default_settings import RETRY_TIMES
from scrapy.spiders import CrawlSpider, Rule
from scrapy.linkextractors.lxmlhtml import LxmlLinkExtractor
from scrapy.linkextractors import LinkExtractor
from scrapy import signals
from scrapy.http import Request
from scrapy.utils.httpobj import urlparse_cached
from scrapper_base import LinkSpider, DuplicatesPipeline, KeywordMiddleware, LinkItem

from pgpdump.data import AsciiData
from pgpdump.packet import SignaturePacket, PublicKeyPacket, PublicSubkeyPacket, UserIDPacket

# scrapy api imports
from scrapy import signals
from twisted.internet import reactor
from scrapy.crawler import Crawler
from scrapy.settings import Settings


logger = logging.getLogger(__name__)
coloredlogs.install(level=logging.INFO)


def spider_closing(spider):
    """
    Activates on spider closed signal
    """
    logger.info("Spider closed: %s" % spider)
    if True:
        reactor.stop()


def get_group_id(url):
    """
    Extracts group id from the url from metafile
    :param url: 
    :return: 
    """
    base = 'maven2/'
    pos = url.find(base)
    if pos < 0:
        raise ValueError('Base not found in the URL')

    url2 = url[pos+len(base):]
    return url2.replace('/', '.')


def strkey(item):
    """
    Returns the str key for the item
    :param item: 
    :return: 
    """
    return '%s:%s:%s' % (item['group_id'], item['artifact_id'], item['version'])


def get_maven_id_from_url(url):
    """
    Returns group id, artifact id from the url
    :param url: 
    :return: 
    """
    burl = utils.strip_leading_slash(url)
    artifact_id = utils.get_last_url_segment(burl)
    group_id = get_group_id(burl)
    return group_id, artifact_id


class DbPipeline(object):
    """
    Storing items to the database
    """
    def __init__(self, crawler, *args, **kwargs):
        self.session = None
        self.app = None
        logger.info('New DB pipeline created %s' % crawler)

    @classmethod
    def from_crawler(cls, crawler, *args, **kwargs):
        return cls(crawler)

    def open_spider(self, spider):
        logger.info('Spider opened %s' % spider)
        logger.info('Spider session: %s' % spider.app.session)
        self.session = spider.app.session
        self.app = spider.app

    def close_spider(self, spider):
        logger.info('Spider closed %s' % spider)

    def pom_exists(self, pomItem, s):
        """
        Returns True if POM already exists
        :param pomItem: 
        :return: 
        """
        res = s.query(MavenArtifact)\
            .filter(MavenArtifact.group_id == pomItem['group_id'])\
            .filter(MavenArtifact.artifact_id == pomItem['artifact_id'])\
            .filter(MavenArtifact.version_id == pomItem['version'])\
            .one_or_none()
        return res is not None

    def asc_exists(self, ascItem, s):
        """
        Returns True if POM already exists
        :param pomItem: 
        :return: 
        """
        res = s.query(MavenSignature)\
            .filter(MavenSignature.group_id == ascItem['group_id'])\
            .filter(MavenSignature.artifact_id == ascItem['artifact_id'])\
            .filter(MavenSignature.version_id == ascItem['version'])\
            .one_or_none()
        return res is not None

    def process_item(self, item, spider):
        """
        Process item for persisting
        :param item: 
        :param spider: 
        :return: 
        """
        try:
            s = self.session()
            if isinstance(item, (PomItem, type(PomItem()), type(PomItem))):
                self.store_pom(item, s)
            elif isinstance(item, (AscItem, type(AscItem()), type(AscItem))):
                self.store_asc(item, s)
            elif isinstance(item, (ArtifactItem, type(ArtifactItem()), type(ArtifactItem))):
                pass
            elif isinstance(item, LinkItem):
                pass
            else:
                logger.warning('Unknown item: %s type %s' % (item, type(item)))
                return

            s.commit()
            s.flush()  # writes changes to DB
            s.expunge_all()  # removes objects from session
        except Exception as e:
            logger.warning('Exception in storing key %s' % e)

        finally:
            utils.silent_close(s)
            s = None
        return item

    def store_pom(self, item, s):
        """
        Store POM file
        :param item: 
        :param s: 
        :return: 
        """
        if self.pom_exists(item, s):
            logger.debug('POM Already exists %s' % strkey(item))
            return

        logger.info('Storing pom: %s' % strkey(item))

        rec = MavenArtifact()
        rec.artifact_id = item['artifact_id']
        rec.group_id = item['group_id']
        rec.artifact_id = item['artifact_id']
        rec.version_id = item['version']
        rec.pom_file = item['body']
        s.add(rec)

    def store_asc(self, item, s):
        """
        Stores ASC file
        :param item: 
        :param s: 
        :return: 
        """
        if self.asc_exists(item, s):
            logger.debug('ASC Already exists %s' % strkey(item))
            return

        rec = MavenSignature()
        rec.artifact_id = item['artifact_id']
        rec.group_id = item['group_id']
        rec.artifact_id = item['artifact_id']
        rec.version_id = item['version']
        rec.sig_file = item['body']

        rec.sig_hash = item['sig_hash']
        rec.sig_key_id = item['sig_key_id']
        rec.sig_version = item['sig_version']
        rec.sig_pub_alg = item['sig_pub_alg']
        rec.sig_created = item['sig_created']
        rec.sig_expires = item['sig_expires']

        s.add(rec)
        logger.info('Storing asc: %s' % strkey(item))


class MavenDataSpider(LinkSpider):
    """
    Maven spider downloading maven repo sitemap / structure, POM files, pom.asc files.
    """
    name = 'maven'
    AUTOTHROTTLE_ENABLED = True

    allowed_domains = ['repo1.maven.org']
    allowed_kw = ['repo1.maven.org']

    start_urls = ['https://repo1.maven.org/']

    rules = (
        Rule(LxmlLinkExtractor(allow=('.+maven2/$'),  # '.+/$'
                               deny=(

                                   '.+Default\.aspx\?p=.+',
                                   '.+Default\.aspx\?s=.+',
                                   '.+xml', '.+pom', '.+jar',
                                   '.+asc', '.+md5', '.+sha1',
                               ),
                               process_value='process_link'),
             callback='parse_page', follow=False),
    )

    custom_settings = {
        'SPIDER_MIDDLEWARES': {
            'scrapper_base.KeywordMiddleware': 543,
            'scrapy.spidermiddlewares.offsite.OffsiteMiddleware': 545
        },

        'ITEM_PIPELINES': {
            # Use if want to prevent duplicates, otherwise useful for frequency analysis
            # 'scrapper.DuplicatesPipeline': 10,
            'scrapper_maven_data.DbPipeline': 10
        },

        'AUTOTHROTTLE_ENABLED': True,
        'DOWNLOAD_DELAY': 0.5,
        'CONCURRENT_REQUESTS_PER_IP': 32,
        'CONCURRENT_REQUESTS_PER_DOMAIN': 32,
        'AUTOTHROTTLE_TARGET_CONCURRENCY': 32,
        'RETRY_ENABLED': True,
        'RETRY_TIMES': 3,

    }

    # 'SCHEDULER_DISK_QUEUE': 'queuelib.queue.FifoSQLiteQueue',

    def __init__(self, *a, **kw):
        super(MavenDataSpider, self).__init__(*a, **kw)
        self.link_queue_mode = True
        self.app = kw.get('app', None)
        self.session = kw.get('dbsess', None)
        logger.info('App: %s, sess: %s, self: %s' % (self.app, self.session, self))
        logger.info('Args: %s, kwargs: %s' % (a, kw))

    def should_follow_link(self, link, response):
        should_follow = super(MavenDataSpider, self).should_follow_link(link, response)
        # logger.debug("--link(%s) %s" % (1 if should_follow else 0, link))
        return should_follow

    def process_link(self, val):
        """
        Process the link extracted by the link extractor.
        Do not follow links to the version directories. Matching regex [number].
        :param val:
        :return:
        """
        last_segment = val
        last_slash = val[-1] == '/'
        if last_slash:
            last_segment = val[0:-1]

        last_segment = last_segment.rsplit('/', 1)[1]
        if self.is_version_folder(last_segment):
            logger.info('Skipping link with version: %s' % val)
            return None

        logger.debug('Link: %s' % val)
        return None

    @staticmethod
    def remove_prefix(text, prefix):
        return text[text.startswith(prefix) and len(prefix):]

    def is_version_folder(self, last_segment):
        """
        Returns True if the given folder is maven artifact version folder.
        :param last_segment:
        :return:
        """
        if re.match('^([rv]|commit)?([0-9]+)([.\-]|$).*', last_segment, flags=re.IGNORECASE):
            return True
        else:
            return False

    def start_requests(self):
        """
        Initial requests
        :return: 
        """
        logger.info('Loading requests')
        for req in self.app.start_requests():
            yield req

    def parse_pom(self, response):
        """
        Parses POM requests
        :param response: 
        :return: 
        """
        item = PomItem()
        item['url'] = response.url
        item['version'] = response.meta['max_version']
        item['artifact_id'] = response.meta['artifact_id']
        item['group_id'] = response.meta['group_id']
        item['body'] = response.body

        yield item

        # Generate asc request
        pom_asc_link = response.url + '.asc'
        yield Request(pom_asc_link, callback=self.parse_asc, meta=dict(response.meta))

    def parse_asc(self, response):
        """
        Parses PGP signature 
        :param response: 
        :return: 
        """
        item = AscItem()
        item['url'] = response.url
        item['version'] = response.meta['max_version']
        item['artifact_id'] = response.meta['artifact_id']
        item['group_id'] = response.meta['group_id']
        item['body'] = response.body

        # Parse sig.
        pgp = AsciiData(response.body)
        packets = list(pgp.packets())
        sig_packet = packets[0]
        if isinstance(sig_packet, SignaturePacket):
            item['sig_hash'] = sig_packet.hash_algorithm
            item['sig_key_id'] = sig_packet.key_id
            item['sig_version'] = sig_packet.sig_version
            item['sig_pub_alg'] = sig_packet.pub_algorithm
            item['sig_created'] = sig_packet.creation_time
            item['sig_expires'] = sig_packet.expiration_time

        yield item

    def pom_exists(self, group_id, artifact_id, version_id, s):
        """
        Returns True if POM already exists
        :param group_id: 
        :param artifact_id: 
        :param version_id: 
        :param s: 
        :return: 
        """
        res = s.query(MavenArtifact)\
            .filter(MavenArtifact.group_id == group_id)\
            .filter(MavenArtifact.artifact_id == artifact_id)\
            .filter(MavenArtifact.version_id == version_id)\
            .one_or_none()
        return res is not None

    def parse_page(self, response):
        """
        General page parser
        :param response: 
        :return: 
        """
        links_visit = set()
        links = set()
        for link in LxmlLinkExtractor(allow=(), deny=()).extract_links(response):
            # Add all links except up link.
            if link.text != '../':
                links.add(link.url)

        # Links extracted from the current page.
        # Extract links only if landed in the artifact directory.
        is_artifact = False
        art_conf = 0
        if len(links) < 100:
            art_conf += 3

        versions = []
        misc_files = []
        for link in links:
            if link.endswith('/maven-metadata.xml'):
                is_artifact = True

            last_segment = link
            last_slash = link[-1] == '/'

            if last_slash:
                last_segment = link[0:-1]
            last_segment = last_segment.rsplit('/', 1)[1]

            if self.is_version_folder(last_segment):
                art_conf += 1
                versions.append({'v': last_segment, 'l': self.remove_prefix(link, response.url)})

            elif link != response.url:
                misc_files.append(self.remove_prefix(link, response.url))

        # TODO: if non-standard format, download also maven-metadata.xml
        # Store only artifacts related URLs
        if is_artifact or art_conf > 5:
            logger.info('New artifact(%s), confidence(%s): %s' % (is_artifact, art_conf, response.url))
            item = ArtifactItem()
            item['url'] = response.url
            item['versions'] = versions
            item['misc_files'] = misc_files
            item['artifact_detected'] = is_artifact
            item['confidence'] = art_conf
            yield item

            # Generate request for the newest version
            if is_artifact and len(versions) > 0:
                cur_sess = None
                try:
                    cur_sess = self.session()

                    burl = utils.strip_leading_slash(response.url)
                    max_version = sorted([x['v'] for x in versions], cmp=vv.version_cmp, reverse=True)[0]
                    grp_id, art_id = get_maven_id_from_url(burl)

                    if not self.pom_exists(grp_id, art_id, max_version, cur_sess):
                        logger.info('Enqueueing artifact %s %s %s' % (grp_id, art_id, max_version))
                        meta = {'burl': burl, 'artifact_id': art_id, 'group_id': grp_id,
                                'max_version': max_version}
                        art_url = '%s/%s' % (burl, max_version)
                        art_base_name = '%s-%s' % (art_id, max_version)
                        pom_link = '%s/%s.pom' % (art_url, art_base_name)
                        yield Request(pom_link, callback=self.parse_pom, meta=dict(meta))

                except Exception as e:
                    logger.debug('Exception in POM exist check: %s, self: %s, sess: %s' % (e, self, self.session))
                    logger.debug(traceback.format_exc())
                    utils.silent_close(cur_sess)

            # Case: maven-metadata is present, but we have also another directories here -> crawl it.
            # otherwise do not follow any more links from this page.
            base_url = response.url
            if base_url[-1] != '/':
                base_url += '/'

            links = [base_url + x for x in misc_files if x.endswith('/')]

        # Links post processing
        for link in links:
            if not self.should_follow_link(link, response):
                continue
            links_visit.add(link)

        logger.debug('Extracted %s links from %s' % (len(links_visit), response.url))
        for link in list(links_visit):
            yield Request(link, callback=self.parse_page)


class MainMavenDataWrapper(object):
    """
    Main running class for the maven scraper. 
    Argument processing, environment preparation, DB connection. 
    Starts the crawling process.
    """
    def __init__(self):
        self.args = None
        self.spider = None

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

    def start_requests(self):
        """
        Generates start requests from the sitemap.
        :return: 
        """
        # Load sitemap JSON - generate queues
        if self.args.sitemap_json is None:
            yield Request('https://repo1.maven.org/maven2/', callback=self.spider.parse_page, meta=dict())
            return

        for req in self.gen_links(self.args.sitemap_json):
            yield req

    def gen_links(self, sitemap):
        """
        Generate link links for files to download
        :return: 
        """
        ctr = 0
        # links = []
        with open(sitemap, 'r') as fh:
            logger.info('Loading sitemap file %s' % sitemap)

            js = json.load(fh)
            logger.info('Loaded, number of packages: %s' % len(js))

            for rec in js:
                try:
                    burl = utils.strip_leading_slash(rec['url'])
                    artifact_detected = rec['artifact_detected']
                    if not artifact_detected:
                        # logger.debug('Not an artifact: %s' % burl)
                        continue

                    artifact_id = utils.get_last_url_segment(burl)
                    versions = [x['v'] for x in rec['versions']]
                    if len(versions) == 0:
                        # logger.debug('No versions for %s' % artifact_id)
                        continue

                    group_id = get_group_id(burl)
                    max_version = sorted(versions, cmp=vv.version_cmp, reverse=True)[0]
                    url = '%s/%s' % (burl, max_version)
                    base_name = '%s-%s' % (artifact_id, max_version)
                    meta = {'burl': burl, 'artifact_id': artifact_id, 'group_id': group_id, 'max_version': max_version}

                    pom_link = '%s/%s.pom' % (url, base_name)
                    pom_asc_link = '%s/%s.pom.asc' % (url, base_name)

                    yield Request(pom_link, callback=self.spider.parse_pom, meta=dict(meta))
                    # yield Request(pom_asc_link, callback=self.spider.parse_asc, meta=dict(meta))
                    ctr += 1

                except Exception as e:
                    logger.error('Exception in parsing %s' % e)
                    logger.debug(traceback.format_exc())

        # logger.info('Generated %s links' % len(links))
        # return links

    def kickoff(self):
        """
        Starts a new crawler
        :return: 
        """
        settings = Settings()

        # settings.set("USER_AGENT", "Test")
        settings.set('JOBDIR', self.args.data_dir)
        self.spider = MavenDataSpider()

        # Wrap with crawler, configure
        crawler = Crawler(self.spider, settings)
        crawler.signals.connect(spider_closing, signal=signals.spider_closed)

        logger.info('Starting crawler')
        crawler.crawl(self.spider, app=self, dbsess=self.session)

        self.spider = crawler.spider
        self.spider.link_queue_mode = False
        if self.args.debug:
            coloredlogs.install(level=logging.DEBUG)

        # Keeping thread working
        reactor.run()

    def work(self):
        """
        Entry point after argument processing.
        :return: 
        """
        self.config_file = self.args.config
        self.init_config()
        self.init_db()

        self.kickoff()

    def main(self):
        """
        Main entry point
        :return: 
        """
        parser = argparse.ArgumentParser(description='Maven data crawler')

        parser.add_argument('--data', dest='data_dir', default='.',
                            help='Data directory output')

        parser.add_argument('--scratch', dest='scratch_dir', default='.',
                            help='Scratch directory output')

        parser.add_argument('-t', dest='threads', default=1,
                            help='Number of download threads to use')

        parser.add_argument('--debug', dest='debug', default=False, action='store_const', const=True,
                            help='Debugging logging')

        parser.add_argument('--dry-run', dest='dry_run', default=False, action='store_const', const=True,
                            help='Dry run - no file will be overwritten or deleted')

        parser.add_argument('--continue', dest='continue1', default=False, action='store_const', const=True,
                            help='Continue from the previous attempt')

        parser.add_argument('--continue-frac', dest='continue_frac', default=None, type=float,
                            help='Fraction of the file to start reading from')

        parser.add_argument('--link-file', dest='link_file', nargs=argparse.ZERO_OR_MORE, default=[],
                            help='JSON file generated by censys_links.py')

        parser.add_argument('--link-idx', dest='link_idx', nargs=argparse.ZERO_OR_MORE, default=[],
                            help='Link indices to process')

        parser.add_argument('--file', dest='file', nargs=argparse.ZERO_OR_MORE, default=[],
                            help='LZ4 files to process')

        parser.add_argument('--url', dest='url', nargs=argparse.ZERO_OR_MORE, default=[],
                            help='LZ4 URL to process')

        parser.add_argument('--mpi', dest='mpi', default=False, action='store_const', const=True,
                            help='Use MPI distribution')

        parser.add_argument('--sitemap-json', dest='sitemap_json', default=None,
                            help='JSON sitemap')

        parser.add_argument('--config', dest='config', default=None,
                            help='Config file')

        self.args = parser.parse_args()

        if self.args.debug:
            coloredlogs.install(level=logging.DEBUG)

        self.work()


def main():
   app = MainMavenDataWrapper()
   app.main()


if __name__ == '__main__':
    main()



