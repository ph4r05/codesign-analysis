#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import argparse
import logging
import coloredlogs
import collections
import json
import random
import requests
import utils
import re
from lxml import html

from requests.auth import HTTPBasicAuth

logger = logging.getLogger(__name__)
coloredlogs.install(level=logging.DEBUG)


def timefix(x):
    if 'T' in x:
        return x[:x.find('T')]
    return x


def get_last_link(x):
    m = re.match(r'^<(.+?)>; rel="next", <(.+?)>; rel="last"', x)
    return m.group(2)


def main():
    parser = argparse.ArgumentParser(description='GitHub contributors stats')
    parser.add_argument('-c', dest='config', default=None, help='JSON config file')
    parser.add_argument('files', nargs=argparse.ZERO_OR_MORE, default=[], help='files to process')

    args = parser.parse_args()
    config_file = args.config

    # load config with access tokens
    auths=[]
    with open(config_file, 'r') as fh:
        config = json.load(fh, object_pairs_hook=collections.OrderedDict)
        res_tmp = config['res']
        random.shuffle(res_tmp)
        for user in res_tmp:
            auths.append(HTTPBasicAuth(user['usr'], user['token']))

    print('login;contribs;repos;avg')

    def_info = collections.OrderedDict()
    def_info['contribs'] = 0
    def_info['repos'] = 0
    def_info['cons'] = []
    contribs = collections.defaultdict(lambda: collections.OrderedDict(def_info))

    already_loaded = set()
    not_found = []
    for fl in args.files:
        data = open(fl).read().split('\n')
        for repo in data:
            repo_parts = utils.strip_leading_slash(repo).split('/')
            author = utils.strip(repo_parts[-2])
            repo_name = utils.strip(repo_parts[-1])

            url = 'https://api.github.com/repos/%s/%s' % (author, repo_name)
            contrib_url = 'https://api.github.com/repos/%s/%s/contributors' % (author, repo_name)

            if url in already_loaded:
                continue

            already_loaded.add(url)
            res = requests.get(contrib_url, timeout=10, auth=random.choice(auths))
            js = res.json()
            if js is None:
                not_found.append(url)
                continue

            for contrib in js:
                login = contrib['login']
                usr = contribs[login]
                usr['contribs'] += contrib['contributions']
                usr['repos'] += 1
                usr['cons'].append(contrib['contributions'])

    for login in contribs:
        rec = contribs[login]
        rdat = [
            login,
            rec['contribs'],
            rec['repos'],
            float(rec['contribs']) / float(rec['repos'])
        ]

        print(';'.join([str(x) for x in rdat]))


# Launcher
if __name__ == "__main__":
    main()

