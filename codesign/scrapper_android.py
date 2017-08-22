#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# http://sangaline.com/post/advanced-web-scraping-tutorial/
#

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
from database import MavenArtifact, MavenSignature, MavenArtifactIndex
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

from lxml import html
from collections import OrderedDict
from apk_parse.apk import APK

from pgpdump.data import AsciiData
from pgpdump.packet import SignaturePacket, PublicKeyPacket, PublicSubkeyPacket, UserIDPacket

# scrapy api imports
from scrapy import signals
from twisted.internet import reactor
from scrapy.crawler import Crawler
from scrapy.settings import Settings
import sqlalchemy

logger = logging.getLogger(__name__)
coloredlogs.install(level=logging.INFO)


def spider_closing(spider):
    """
    Activates on spider closed signal
    """
    logger.info("Spider closed: %s" % spider)
    if True:
        reactor.stop()


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

    def index_load(self, groupId, artifactId, s):
        """
        Returns True if index already exists
        :param pomItem: 
        :return: 
        """
        res = s.query(MavenArtifactIndex)\
            .filter(MavenArtifactIndex.group_id == groupId)\
            .filter(MavenArtifactIndex.artifact_id == artifactId)\
            .one_or_none()
        return res

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
                pass #self.store_pom(item, s)
            elif isinstance(item, (AscItem, type(AscItem()), type(AscItem))):
                pass  #self.store_asc(item, s)
            elif isinstance(item, (ArtifactItem, type(ArtifactItem()), type(ArtifactItem))):
                pass  #self.store_index(item, s)
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


class AndroidDataSpider(LinkSpider):
    """
    Maven spider downloading maven repo sitemap / structure, POM files, pom.asc files.
    """
    name = 'android'

    allowed_domains = ['www.apkmirror.com']
    allowed_kw = ['apkmirror.com']

    start_urls = ['https://www.apkmirror.com/page/1/']

    rules = (
        Rule(LxmlLinkExtractor(allow=('.+www.apkmirror.com/page/[0-9]+/?$'),  # '.+/$'
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
            'scrapy.spidermiddlewares.offsite.OffsiteMiddleware': 545,
            'scrapper_middleware.RandomUserAgentMiddleware': 546,
        },

        'ITEM_PIPELINES': {
            # Use if want to prevent duplicates, otherwise useful for frequency analysis
            # 'scrapper.DuplicatesPipeline': 10,
            'scrapper_android.DbPipeline': 10
        },

        'AUTOTHROTTLE_ENABLED': True,
        'DOWNLOAD_DELAY': 3,
        'CONCURRENT_REQUESTS_PER_IP': 1,
        'CONCURRENT_REQUESTS_PER_DOMAIN': 1,
        'AUTOTHROTTLE_TARGET_CONCURRENCY': 1,
        'RETRY_ENABLED': True,
        'RETRY_TIMES': 3,
        'COOKIES_ENABLED': True,
        'COOKIED_DEBUG': True,
        'DUPEFILTER_DEBUG': True,
        'USER_AGENT': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36',

    }

    # 'SCHEDULER_DISK_QUEUE': 'queuelib.queue.FifoSQLiteQueue',

    def __init__(self, *a, **kw):
        super(AndroidDataSpider, self).__init__(*a, **kw)
        self.link_queue_mode = True
        self.app = kw.get('app', None)
        self.session = kw.get('dbsess', None)
        logger.info('App: %s, sess: %s, self: %s' % (self.app, self.session, self))
        logger.info('Args: %s, kwargs: %s' % (a, kw))

    def should_follow_link(self, link, response):
        should_follow = super(AndroidDataSpider, self).should_follow_link(link, response)
        # logger.debug("--link(%s) %s" % (1 if should_follow else 0, link))
        return should_follow

    def process_link(self, val):
        """
        Process the link extracted by the link extractor.
        Do not follow links to the version directories. Matching regex [number].
        :param val:
        :return:
        """
        return None

    def start_requests(self):
        """
        Initial requests
        :return: 
        """
        logger.info('Loading requests')
        for req in self.app.start_requests():
            yield req

    def parse_page(self, response):
        """
        General page parser
        :param response: 
        :return: 
        """
        links_visit = set()
        links = set()
        for link in LxmlLinkExtractor(allow=(), deny=()).extract_links(response):
            links.add(link.url)

        logger.info('Current url: %s' % response.url)
        logger.info('Current resp: %s' % response)

        # Search result - container element
        lists = response.xpath('//div[@id="primary"]//div[@class="listWidget"]')
        for list_widget in lists:
            logger.debug('List widget: %s' % list_widget)
            eapp = list_widget.xpath('div[@class="appRow"]')
            einfo = list_widget.xpath('div[@class="infoSlide"]')

            if len(eapp) == 0:
                logger.warning('No results')
                return

            for eapp1 in eapp:
                logger.debug(eapp1)

                #ahref = eapp1.xpath('div/div/div/h5/a')[0]
                #link = ahref.attrib['href']
                #title = ahref.xpath('text()')
                #logger.debug('Title / link %s %s ' % (title, link))

        logger.debug('Extracted %s links from %s' % (len(links_visit), response.url))
        for link in list(links_visit):
            pass
            # yield Request(link, callback=self.parse_page)


class MainAndroidDataWrapper(object):
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
        Generates start requests.
        :return: 
        """
        for page in range(1, 3):  # TODO: more pages
            yield Request('https://www.apkmirror.com/page/%d/' % page,
                          callback=self.spider.parse_page, meta=dict(
                    {
                        'page': page,
                        'dont_obey_robotstxt': True
                    }))

    def kickoff(self):
        """
        Starts a new crawler
        :return: 
        """
        settings = Settings()

        # settings.set("USER_AGENT", "Test")
        settings.set('JOBDIR', self.args.data_dir)
        self.spider = AndroidDataSpider()

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
        parser = argparse.ArgumentParser(description='Android data crawler')

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
   app = MainAndroidDataWrapper()
   app.main()


if __name__ == '__main__':
    main()



