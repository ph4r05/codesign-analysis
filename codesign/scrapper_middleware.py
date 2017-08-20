#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import random


logger = logging.getLogger(__name__)


USER_AGENT_LIST = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.90 Safari/537.36',
    'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36',
]


class RandomUserAgentMiddleware(object):
    """
    Sets user agent randomly to the scrapper
    """

    def process_request(self, request, spider):
        """
        Process request hook, updating the user agent being used
        :param request: 
        :param spider: 
        :return: 
        """
        ua_list = None
        try:
            ua_list = spider.crawler.settings.get('USER_AGENT_LIST')
        except:
            pass

        if ua_list is None or len(ua_list) == 0:
            ua_list = USER_AGENT_LIST

        user_agent = random.choice(ua_list)
        request.headers.setdefault('User-Agent', user_agent)
        # return request



