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

from requests.auth import HTTPBasicAuth

logger = logging.getLogger(__name__)
coloredlogs.install(level=logging.DEBUG)


def main():
    parser = argparse.ArgumentParser(description='GitHub repo stats')
    parser.add_argument('-c', dest='config', default=None, help='JSON config file')
    parser.add_argument('files', nargs=argparse.ZERO_OR_MORE, default=[], help='files to process')

    args = parser.parse_args()
    config_file = args.config

    # load config with access tokens
    with open(config_file, 'r') as fh:
        config = json.load(fh, object_pairs_hook=collections.OrderedDict)
        res_tmp = config['res']
        random.shuffle(res_tmp)
        user = res_tmp[0]
        auth = HTTPBasicAuth(user['usr'], user['token'])
        logger.info('Going to use %s' % user['usr'])

    print('repo;stars;watchers;forks;open_issues;subscribers_count;network_count;size;language;'
          'created_at;updated_at;pushed_at;owner')

    not_found = []
    for fl in args.files:
        data = open(fl).read().split('\n')
        for repo in data:
            repo_parts = utils.strip_leading_slash(repo).split('/')
            author = utils.strip(repo_parts[-2])
            repo_name = utils.strip(repo_parts[-1])

            url = 'https://api.github.com/repos/%s/%s' % (author, repo_name)
            res = requests.get(url, timeout=10, auth=auth)
            js = res.json()
            if js is None or 'stargazers_count' not in js:
                not_found.append(url)
                continue

            rdat = [
                '%s/%s' % (author, repo_name),
                js['stargazers_count'],
                js['watchers_count'],
                js['forks'],
                js['open_issues'],
                js['subscribers_count'],
                js['network_count'],
                js['size'],
                js['language'],
                js['created_at'],
                js['updated_at'],
                js['pushed_at'],
                js['owner']['login']
            ]
            print(';'.join([str(x) for x in rdat]))

    print('Repos not found:')
    for x in not_found:
        print('.. %s' % x)


# Launcher
if __name__ == "__main__":
    main()

