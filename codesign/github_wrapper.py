#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
GitHub key downloader.
We use this for academic research on SSH keys entropy.
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
import re
import time
import multiprocessing
import signal
import utils
import collections
import threading
from threading import Lock as Lock
import types
import Queue
from blessed import Terminal
from cmd2 import Cmd
import pexpect
import gc
import mem_top

logger = logging.getLogger(__name__)
coloredlogs.install(level=logging.INFO)


def main():
    args_src = sys.argv
    parser = argparse.ArgumentParser(description='Downloads GitHub SSH keys')
    args, unknown = parser.parse_known_args(args=args_src[1:])
    logger.info('Args: %s' % args)
    logger.info('Unknown: %s' % unknown)

    while True:
        args_to_pass = unknown
        logger.info('Starting a new iteration, args: %s' % args_to_pass)
        child = pexpect.spawnu('python', args_to_pass)
        child.interact(escape_character=None)  # give control of the child to the user
        logger.info('Wrapped process terminated, sleep a while...')
        time.sleep(10)
    sys.argv = args_src


# Launcher
if __name__ == "__main__":
    main()


