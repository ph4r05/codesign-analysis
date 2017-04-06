#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import random


logger = logging.getLogger(__name__)


USER_AGENT_LIST = [
    'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/535.7 (KHTML, like Gecko) Chrome/16.0.912.36 Safari/535.7',
    'Mozilla/5.0 (Windows NT 6.2; Win64; x64; rv:16.0) Gecko/16.0 Firefox/16.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_3) AppleWebKit/534.55.3 KHTML, like Gecko) Version/5.1.3 Safari/534.53.10'
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



