import scrapy
import re
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


class MavenSpider(LinkSpider):
    name = 'maven'
    download_delay = 0.75
    AUTOTHROTTLE_ENABLED = True

    allowed_domains = ['repo1.maven.org']
    allowed_kw = ['repo1.maven.org']

    start_urls = ['https://repo1.maven.org/']

    rules = (
        Rule(LxmlLinkExtractor(allow=('.+/$'),
                               deny=(
                                   '.+Default\.aspx\?p=.+',
                                   '.+Default\.aspx\?s=.+',
                                   '.+xml',
                                   '.+pom',
                                   '.+jar',
                                   '.+asc',
                                   '.+md5',
                                   '.+sha1',
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
        'DOWNLOAD_DELAY': 0.75,
        'CONCURRENT_REQUESTS_PER_IP': 4,
        'CONCURRENT_REQUESTS_PER_DOMAIN': 4,
        'AUTOTHROTTLE_TARGET_CONCURRENCY': 4,

    }

    def shoud_follow_link(self, link, response):
        should_follow = super(MavenSpider, self).shoud_follow_link(link, response)
        logger.debug("--link(%s) %s" % (1 if should_follow else 0, link))
        return should_follow

    def process_link(self, val):
        """
        Process the link extracted by the link extractor.
        Do not follow links to the version directories. Matching regex [number].
        :param val:
        :return:
        """
        if re.match('^[0-9]+\..*', val):
            logger.info('Skipping link with version: %s' % val)
            return None

        return val

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

            if re.match('^[0-9]+[.\-].*', last_segment):
                art_conf += 1
                versions.append({'v': last_segment, 'l': link})

            elif link != response.url:
                misc_files.append(link)

        # Store only artifacts related URLs
        if is_artifact or art_conf > 5:
            logger.info('New artifact(%s), confidence(%s): %s' % (is_artifact, art_conf, response.url))
            item = ArtifactItem()
            item['url'] = response.url
            item['versions'] = versions
            item['misc_files'] = misc_files
            yield item

            # Do not follow any more links from this directory
            return

        # Links post processing
        for link in links:
            if not self.shoud_follow_link(link, response):
                continue
            links_visit.add(link)

        logger.debug('Extracted %s links from %s' % (len(links_visit), response.url))
        for link in list(links_visit):
            yield Request(link)





