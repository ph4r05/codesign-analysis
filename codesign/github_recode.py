#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
GitHub data recoder.
Takes old json format dump, creates a new json format dump

"""

import os
import sys
import inspect
import resource

currentdir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
parentdir = os.path.dirname(currentdir)
sys.path.insert(0, parentdir)


import logging
import coloredlogs
import traceback
import json
import argparse
from collections import OrderedDict, namedtuple

logger = logging.getLogger(__name__)
coloredlogs.install(level=logging.DEBUG)


class GitHubRecoder(object):
    """
    GitHub Recoder
    """

    def __init__(self, ifile, ofile, skip_non_rsa, *args, **kwargs):
        self.ifile = ifile
        self.ofile = ofile
        self.skip_non_rsa = skip_non_rsa

    def work(self):
        logger.info('Starting...')
        with open(self.ofile, 'w') as fho:
            with open(self.ifile, 'r') as fhi:
                for rec in fhi:
                    js = json.loads(rec, object_pairs_hook=OrderedDict)
                    if self.skip_non_rsa:
                        if 'mod' not in js:
                            continue
                        if js['mod'] is None:
                            continue
                        if len(js['mod']) <= 5:
                            continue

                    js['n'] = js['mod']
                    del js['mod']
                    del js['raw']
                    js['source'] = [js['id']]

                    rec_out = json.dumps(js)
                    fho.write(rec_out + '\n')


def main():
    args_src = sys.argv
    parser = argparse.ArgumentParser(description='Export GitHub SSH keys')
    parser.add_argument('-i', '--input', dest='input_file', default=None, help='JSON input file')
    parser.add_argument('-o', '--output', dest='output_file', default=None, help='JSON output file')
    parser.add_argument('--skip-nonrsa', dest='skip_nonrsa', default=False, action='store_const', const=True,
                        help='Skip non-RSA keys')
    args = parser.parse_args(args=args_src[1:])

    logger.info('GitHub recoder started, args: %s' % args)
    l = GitHubRecoder(ifile=args.input_file, ofile=args.output_file, skip_non_rsa=args.skip_nonrsa)
    l.work()


# Launcher
if __name__ == "__main__":
    main()




