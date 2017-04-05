import scrapy
import re
import argparse
import logging
import coloredlogs
from urlparse import urlparse
import scrapy
from scrapy.spiders import CrawlSpider, Rule
from scrapy.linkextractors.lxmlhtml import LxmlLinkExtractor
from scrapy.linkextractors import LinkExtractor
from scrapy import signals
from scrapy.http import Request
from scrapy.utils.httpobj import urlparse_cached
from scrapper_base import LinkSpider, DuplicatesPipeline, KeywordMiddleware, LinkItem

# scrapy api imports
from scrapy import signals
from twisted.internet import reactor
from scrapy.crawler import Crawler
from scrapy.settings import Settings


logger = logging.getLogger(__name__)
coloredlogs.install(level=logging.DEBUG)


class ArtifactItem(scrapy.Item):
    """
    Basic object for link extraction.
    Initialized in parse_obj, yielded and saved to the JSON result file.
    """
    url = scrapy.Field()
    versions = scrapy.Field()
    misc_files = scrapy.Field()
    artifact_detected = scrapy.Field()
    confidence = scrapy.Field()


class MavenDataSpider(LinkSpider):
    name = 'maven'
    download_delay = 0.75
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
             callback='parse_obj', follow=False),
    )

    custom_settings = {
        'SPIDER_MIDDLEWARES': {
            'scrapper_base.KeywordMiddleware': 543,
            'scrapy.spidermiddlewares.offsite.OffsiteMiddleware': 545
        },

        'ITEM_PIPELINES': {
            # Use if want to prevent duplicates, otherwise useful for frequency analysis
            #'scrapper.DuplicatesPipeline': 10,
        },

        'AUTOTHROTTLE_ENABLED': True,
        'DOWNLOAD_DELAY': 5.75,
        'CONCURRENT_REQUESTS_PER_IP': 1,
        'CONCURRENT_REQUESTS_PER_DOMAIN': 1,
        'AUTOTHROTTLE_TARGET_CONCURRENCY': 1,

    }

    def __init__(self, *a, **kw):
        super(MavenDataSpider, self).__init__(*a, **kw)
        self.link_queue_mode = True
        self.app = None

    def shoud_follow_link(self, link, response):
        should_follow = super(MavenDataSpider, self).shoud_follow_link(link, response)
        logger.debug("--link(%s) %s" % (1 if should_follow else 0, link))
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

    def parse_obj(self, response):
        """
        Base parsing routine - pure link extractor.
        Extract only links ending in the artifact directory.
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

            # Case: maven-metadata is present, but we have also another directories here -> crawl it.
            # otherwise do not follow any more links from this page.
            base_url = response.url
            if base_url[-1] != '/':
                base_url += '/'

            links = [base_url + x for x in misc_files if x.endswith('/')]

        # Links post processing
        for link in links:
            if not self.shoud_follow_link(link, response):
                continue
            links_visit.add(link)

        logger.debug('Extracted %s links from %s' % (len(links_visit), response.url))
        for link in list(links_visit):
            yield Request(link, callback=self.parse_obj)


def spider_closing(spider):
    """
    Activates on spider closed signal
    """
    logger.info("Spider closed: %s" % spider)
    if True:
        reactor.stop()


class MainMavenDataWrapper(object):
    def __init__(self):
        self.args = None
        self.spider = None

    def kickoff(self):
        """
        Starts a new crawler
        :return: 
        """
        settings = Settings()

        # settings.set("USER_AGENT", "Test")
        self.spider = MavenDataSpider()
        self.spider.app = self

        # Wrap with crawler, configure
        crawler = Crawler(self.spider, settings)
        crawler.signals.connect(spider_closing, signal=signals.spider_closed)
        crawler.crawl(self.spider)
        crawler.spider.app = self

        # Keeping thread working
        reactor.run()

    def work(self):
        """
        Entry point after argument processing.
        :return: 
        """
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

        self.args = parser.parse_args()

        if self.args.debug:
            coloredlogs.install(level=logging.DEBUG)

        self.work()


def main():
   app = MainMavenDataWrapper()
   app.main()


if __name__ == '__main__':
    main()



