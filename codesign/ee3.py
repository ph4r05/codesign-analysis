#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
TSL processor - testing all certificates
"""


import base64, textwrap, time, random, datetime
import logging
import coloredlogs
import itertools
import json
from json import JSONEncoder
import decimal
import os
import sys
import collections
import argparse
import socket
import re
import logging
from lxml import html

# import utils
from past.builtins import cmp
import requests

logger = logging.getLogger(__name__)
coloredlogs.install(level=logging.DEBUG)


# url = 'https://ec.europa.eu/information_society/policy/esignature/trusted-list/tl-mp.xml'
# r = requests.get(url)
# print(r.text)

def certp():
    data = open('tl-ii.xml')
    for idx, cert in enumerate(data):
        with open('/tmp/certs/tl-certs_%02d.pem' % idx, 'w') as fh:
            cert = '-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----\n' % cert
            fh.write(cert)


url = 'https://zep.disig.sk/QESPortal/sk/QESSigner/TrustInfo'
data = requests.get(url).text
tree = html.fromstring(data)
ahrefs = tree.xpath('//a')
idx = -1

already_there = set()
for ahref in ahrefs:
    link = ahref.attrib['href']
    if not link.endswith('xml'):
        continue

    idx += 1
    crtLines = 0
    crtIdx = -1
    rdat = None

    logger.info('Loading %s' % link)
    for at in range(10):
        try:
            rdat = requests.get(link, timeout=10).text
            break
        except:
            pass

    if rdat is None:
        if link == 'https://www.eett.gr/tsl/EL-TSL.xml':
            rdat = open('EL-TSL.xml').read()

    for line in [x.strip() for x in rdat.split('\n')]:
        if len(line) == 0:
            continue

        lline = line.lower()
        if 'certificate' in lline or 'x509' in lline:
            crtLines += 1

        if len(line) < 20:
            continue

        if 'X509Certificate' not in line:
            continue

        crtIdx += 1
        m1 = re.match(r'.*<(ds:)?X509Certificate>(.+?)</(ds:)?X509Certificate>.*', line)
        if m1 is None:
            continue

        dr = '/tmp/cert-cr6-un'
        if not os.path.exists(dr):
            os.mkdir(dr)

        pem = m1.group(2)
        if pem in already_there:
            continue

        already_there.add(pem)
        with open('%s/cert_c%03d_i%03d_ds_%d.pem' % (dr, idx, crtIdx, m1.group(1) is not None), 'w') as fh:
            fh.write('-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----\n' % pem)

