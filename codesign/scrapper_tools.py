#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import datetime
from time import time

import scrapy
from scrapy import signals
from scrapy.exceptions import NotConfigured


logger = logging.getLogger(__name__)


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


class AscItem(scrapy.Item):
    """
    Basic object for link extraction.
    Initialized in parse_obj, yielded and saved to the JSON result file.
    """
    url = scrapy.Field()
    version = scrapy.Field()
    artifact_id = scrapy.Field()
    group_id = scrapy.Field()
    body = scrapy.Field()
    sig_hash = scrapy.Field()
    sig_key_id = scrapy.Field()
    sig_version = scrapy.Field()
    sig_type = scrapy.Field()
    sig_pub_alg = scrapy.Field()
    sig_created = scrapy.Field()
    sig_expires = scrapy.Field()


class PomItem(scrapy.Item):
    """
    Basic object for link extraction.
    Initialized in parse_obj, yielded and saved to the JSON result file.
    """
    url = scrapy.Field()
    version = scrapy.Field()
    artifact_id = scrapy.Field()
    group_id = scrapy.Field()
    body = scrapy.Field()


class PoliteScheduler(object):
    """
    Scheduler that is supposed to take into account the processing delays - something like auto throttle.
    """
    def __init__(self):
        pass

    @classmethod
    def from_crawler(cls, crawler):
        obj = cls()
        crawler.signals.connect(obj.process_request,
                                signal=signals.request_scheduled)
        crawler.signals.connect(obj.process_response,
                                signal=signals.response_downloaded)
        return obj

    def process_request(self, response, request, spider):
        """
        Hook for request processing
        :param response: 
        :param request: 
        :param spider: 
        :return: 
        """
        request.meta['req_sched'] = time()
        return request

    def process_response(self, request, response, spider):
        """
        Hook for response processing
        :param request: 
        :param response: 
        :param spider: 
        :return: 
        """
        now = time()
        start = datetime.datetime(response.meta['download_start'])
        response.meta['resp_dl'] = now
        response.meta['dl_time'] = now - start
        return response


