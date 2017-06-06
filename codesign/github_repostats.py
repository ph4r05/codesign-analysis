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


def commit_time(x):
    return timefix(x['commit']['committer']['date'])


def get_last_link(x):
    '''<https://api.github.com/repositories/8602097/commits?page=2>; rel="next", <https://api.github.com/repositories/8602097/commits?page=6>; rel="last"'''
    m = re.match(r'^<(.+?)>; rel="next", <(.+?)>; rel="last"', x)
    return m.group(2)


def label_num(tree, idx):
    try:
        sub = tree.xpath('//div[@class="table-list-header-toggle states float-left pl-3"]')[0][idx]
        txt = sub.xpath('text()')[1].strip()
        return int(txt[:txt.find(' ')])
    except:
        logger.debug('No num')
        return 0


def main():
    parser = argparse.ArgumentParser(description='GitHub repo stats')
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

    print('repo;stars;watchers;forks;open_issues;subscribers_count;network_count;size;language;'
          'created_at;updated_at;pushed_at;owner;commits;branches;releases;contributors;closed_issues;'
          'first_commit;last_commit;pull_open;pull_closed')

    already_loaded = set()
    not_found = []
    for fl in args.files:
        data = open(fl).read().split('\n')
        for repo in data:
            repo_parts = utils.strip_leading_slash(repo).split('/')
            author = utils.strip(repo_parts[-2])
            repo_name = utils.strip(repo_parts[-1])

            url = 'https://api.github.com/repos/%s/%s' % (author, repo_name)
            main_url = 'https://github.com/%s/%s' % (author, repo_name)
            issues_url = 'https://github.com/%s/%s/issues' % (author, repo_name)
            pulls_url = 'https://github.com/%s/%s/pulls' % (author, repo_name)
            commits_url = 'https://api.github.com/repos/%s/%s/commits' % (author, repo_name)

            if url in already_loaded:
                continue

            already_loaded.add(url)
            res = requests.get(url, timeout=10, auth=random.choice(auths))
            js = res.json()
            if js is None or 'stargazers_count' not in js:
                not_found.append(url)
                continue

            # load num of commits
            res = requests.get(main_url, timeout=10)
            tree = html.fromstring(res.text)
            lis = tree.xpath('//ul[@class="numbers-summary"]//li')

            lidata = [-1] * 4
            for lidx, li in enumerate(lis):
                if lidx > 3:
                    break
                try:
                    lidata[lidx] = int(li.xpath('a/span')[0].text.strip())
                except Exception as e:
                    logger.debug('Excepton in parsing: %s' % e) #html.tostring(li))

            # contributors load
            if lidata[3] == -1:
                url_contrib = js['contributors_url']
                res = requests.get(url_contrib, timeout=10, auth=random.choice(auths))
                jsc = res.json()
                if jsc is not None:
                    lidata[3] = len(jsc)

            # closed issues
            res = requests.get(issues_url, timeout=10)
            tree = html.fromstring(res.text)
            js['closed'] = label_num(tree, 1)

            # commits, first & last
            res = requests.get(commits_url, timeout=10, auth=random.choice(auths))
            cjs = res.json()
            first_commit = commit_time(cjs[0])

            if 'Link' in res.headers:
                last_commit_page_url = get_last_link(res.headers['Link'])
                res = requests.get(last_commit_page_url, timeout=10, auth=random.choice(auths))
                cjs = res.json()
            last_commit = commit_time(cjs[-1])

            # pull requests
            res = requests.get(pulls_url, timeout=10)
            tree = html.fromstring(res.text)
            js['pull_open'] = label_num(tree, 0)
            js['pull_closed'] = label_num(tree, 1)

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
                timefix(js['created_at']),
                timefix(js['updated_at']),
                timefix(js['pushed_at']),
                js['owner']['login'],
                lidata[0],
                lidata[1],
                lidata[2],
                lidata[3],
                js['closed'],
                first_commit,
                last_commit,
                js['pull_open'],
                js['pull_closed']
            ]
            print(';'.join([str(x) for x in rdat]))

    print('Repos not found:')
    for x in not_found:
        print('.. %s' % x)


# Launcher
if __name__ == "__main__":
    main()

