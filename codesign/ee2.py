#!/usr/bin/env python
# -*- coding: utf-8 -*-

import ldap, base64, textwrap, time, random, datetime
import logging
import coloredlogs
import itertools
import json
from json import JSONEncoder
import decimal
import os
import collections
import argparse

# import utils
from past.builtins import cmp


LDAP_SERVER = "ldap://ldap.sk.ee"

MID = "ESTEID (MOBIIL-ID)"
DIGI = "ESTEID (DIGI-ID)"
IDCARD = "ESTEID"
RESIDENT_DIGI = "ESTEID (DIGI-ID E-RESIDENT)"
RESIDENT_MID = "ESTEID (MOBIIL-ID E-RESIDENT)"

AUTH = "Authentication"
SIGN = "Digital Signature"

SLEEP_OK = 6
SLEEP_ERR = 60*10
DEF_ID_FILE = './eeids.txt'
DEF_JSON_FILE = './eeids.json'

# SERIALS = sorted([int(str(x)[7:10]) for x in ISIKUKOODS])
SERIALS = [1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 4, 4, 4, 4, 4, 5, 5, 5, 5, 6, 6, 7, 7, 7, 7, 8, 8, 8, 8, 9, 9, 9, 9, 9, 10, 10, 10, 10, 10, 10, 10, 10, 11, 11, 11, 11, 11, 12, 12, 13, 14, 14, 15, 15, 15, 16, 17, 21, 21, 21, 21, 22, 22, 22, 23, 23, 23, 23, 24, 24, 24, 24, 25, 25, 25, 25, 25, 26, 26, 26, 26, 27, 27, 27, 27, 27, 27, 28, 29, 29, 29, 29, 30, 31, 32, 32, 33, 33, 34, 34, 35, 36, 38, 38, 39, 90, 202, 222, 223, 225, 271, 271, 271, 272, 272, 272, 273, 273, 273, 273, 273, 274, 279, 371, 421, 421, 423, 423, 423, 423, 493, 521, 521, 521, 521, 521, 524, 571, 571, 572, 601, 601, 601, 601, 601, 602, 602, 602, 602, 602, 604, 651, 651, 651, 651, 652, 652, 654]


_ = lambda x: x  # please copypaste from lib/libldap.py
logger = logging.getLogger(__name__)
coloredlogs.install(level=logging.DEBUG)


class LdapError(Exception):
    pass


class AutoJSONEncoder(JSONEncoder):
    """
    JSON encoder trying to_json() first
    """
    DATE_FORMAT = "%Y-%m-%d"
    TIME_FORMAT = "%H:%M:%S"

    def default(self, obj):
        try:
            return obj.to_json()
        except AttributeError:
            return self.default_classic(obj)

    def default_classic(self, o):
        if isinstance(o, set):
            return list(o)
        elif isinstance(o, datetime.datetime):
            return o.strftime("%s %s" % (self.DATE_FORMAT, self.TIME_FORMAT))
        elif isinstance(o, datetime.date):
            return o.strftime(self.DATE_FORMAT)
        elif isinstance(o, datetime.time):
            return o.strftime(self.TIME_FORMAT)
        elif isinstance(o, decimal.Decimal):
            return str(o)
        else:
            return super(AutoJSONEncoder, self).default(o)


def get_pems_from_ldap(idcode, cert_type=None, chip_type=None):
    """
    Fetches the certificate(s) of the idcode owner from SK LDAP.
    """
    if isinstance(idcode, int):
        idcode = str(idcode)

    assert idcode.isdigit() and len(idcode) == 11

    query = []
    if cert_type is not None:
        query.append('ou=%s' % cert_type)
    if chip_type is not None:
        query.append('o=%s' % chip_type)
    query.append('c=EE')

    server = ldap.initialize(LDAP_SERVER)
    q = server.search(','.join(query), ldap.SCOPE_SUBTREE,
                      'serialNumber=%s' % idcode,
                      [])  # ['userCertificate;binary'])

    result = server.result(q, timeout=10)

    if result[0] != ldap.RES_SEARCH_RESULT:
        raise LdapError(_("Unexpected result type."))
    if not result[1]:
        raise LdapError(_("No results from LDAP query."))
    if len(result[1][0]) != 2 or not isinstance(result[1][0][1], dict) \
            or not result[1][0][1].has_key('userCertificate;binary') \
            or not result[1][0][1]['userCertificate;binary'] \
            or not isinstance(result[1][0][1]['userCertificate;binary'], list):
        raise LdapError(_("Unexpected result format."))

    reslist = result[1]
    js = collections.OrderedDict()
    js['id'] = idcode
    js['res'] = []

    for cn, data in reslist:
        cur_rec = collections.OrderedDict()
        cur_rec['dn'] = cn
        if 'cn' in data:
            cur_rec['cn'] = data['cn']
        if 'objectClass' in data:
            cur_rec['oc'] = data['objectClass']
        if 'userCertificate;binary' in data:
            cobjs = data['userCertificate;binary']
            cur_rec['certs'] = [base64.b64encode(xx) for xx in cobjs if xx is not None and len(xx) > 0]
        js['res'].append(cur_rec)
    return js
    #return [_get_pem_from_der(x) for x in result[1][0][1]['userCertificate;binary']]


def _get_pem_from_der(der):
    """
    Converts DER certificate to PEM.
    """
    return "\n".join(("-----BEGIN CERTIFICATE-----",
                      "\n".join(textwrap.wrap(base64.b64encode(der), 64)),
                      "-----END CERTIFICATE-----",))


def add_score(pms, range, score):
    """
    Adds score to the pms
    :param pms:
    :param range:
    :param score:
    :return:
    """
    for x in range:
        pms[x] += score


def normalize(pms):
    """
    Normalizes pms scores to 1
    :param pms:
    :return:
    """
    total = sum(pms)
    fact = 1.0/total
    for x in range(len(pms)):
        pms[x] *= fact
    return pms


def build_serial_pms():
    """
    Probability mass function on serials from collected samples
    :return:
    """
    hists = sorted(SERIALS)
    pms = [0.005] * 1000  # serial pms, baseline score

    # significance groups
    add_score(pms, range(1, 40), 100)
    add_score(pms, range(1, 99), 20)

    add_score(pms, range(200, 230), 6)
    add_score(pms, range(270, 280), 10)
    add_score(pms, range(420, 430), 5)
    add_score(pms, range(520, 530), 5)
    add_score(pms, range(600, 610), 10)
    add_score(pms, range(650, 660), 8)

    # collected data - adding points
    # give away another 100 points in total
    total = len(hists)
    one_pt = 150.0 / float(total)
    for k, g in itertools.groupby(hists, lambda x: x):
        pms[k] += one_pt * len(list(g))

    # normalize for use as pms
    pmsn = normalize(pms)
    return pmsn


def build_serial_dist(pms):
    """
    Builds discrete distribution with probability mass function
    :param pms:
    :return:
    """
    from scipy import stats
    import numpy as np

    xk = np.arange(1000)
    custm = stats.rv_discrete(name='custm', values=(xk, pms))
    return custm


def control_nr(code):
    code = [int(i) for i in code]
    weight1 = [1, 2, 3, 4, 5, 6, 7, 8, 9, 1]
    weight2 = [3, 4, 5, 6, 7, 8, 9, 1, 2, 3]
    sum1 = sum([x*y for x,y in zip(code, weight1)])
    sum2 = sum([x*y for x,y in zip(code, weight2)])
    if sum1 % 11 != 10:
        return str(sum1 % 11)
    elif sum2 % 11 != 10:
        return str(sum2 % 11)
    else:
        return "0"


def random_isikukood(serial_dist=None):
    """
    Generates random personal code / isikukood
    :return:
    """
    century = 0  # random.randint(0, 1)
    sex = random.randint(3, 4)

    d1 = sex + century

    # year - century 0 -> live people.. start with 50
    #        century 1 -> adult people, none :P
    year = random.randint(50, 99)

    # generate random day & month in that year - ordinals
    minord = datetime.date(year=year, month=1, day=1).toordinal()
    maxord = datetime.date(year=year, month=12, day=31).toordinal()
    randord = random.randint(minord, maxord)
    rnddate = datetime.date.fromordinal(randord)

    # serial = random.randint(0, 999)
    serial = random.randint(1, 40)  # small serials
    if serial_dist is not None:
        serial = serial_dist.rvs()

    code = '%d%02d%02d%02d%03d' % (d1, year, rnddate.month, rnddate.day, serial)
    return code + control_nr(code)


def append_to_file(id):
    with open(DEF_ID_FILE, 'a+') as fh:
        fh.write('%s\n' % id)


def append_json_to_file(data):
    with open(DEF_JSON_FILE, 'a+') as fh:
        fh.write('%s\n' % data)


def load_idxs():
    if not os.path.exists(DEF_ID_FILE):
        return []
    with open(DEF_ID_FILE) as fh:
        return [int(x) for x in fh.readlines() if len(x.strip()) > 0]


def load_processed():
    if not os.path.exists(DEF_JSON_FILE):
        return []
    ret = []
    with open(DEF_JSON_FILE) as fh:
        lines = fh.readlines()
        for l in [x.strip() for x in lines if len(x.strip()) > 0]:
            js = json.loads(l)
            ret.append(int(js['id']))
    return ret


def main():
    parser = argparse.ArgumentParser(description='EE loader')

    parser.add_argument('--debug', dest='debug', default=False, action='store_const', const=True,
                        help='Debugging logging')

    parser.add_argument('--pms', dest='pms', default=False, action='store_const', const=True,
                        help='Use observed PMS')

    args = parser.parse_args()
    slp = SLEEP_OK
    hits = 0
    found = []

    loaded = set(load_processed())
    do_first = sorted(list(set([x for x in load_idxs() if x not in loaded])))
    logger.info('Non-processed: %s' % len(do_first))

    pms = build_serial_pms()
    cust_dist = build_serial_dist(pms)
    dist = cust_dist if args.pms else None
    if dist is not None:
        logger.info('Using custom PMS')

    for i in range(50000):
        id = random_isikukood(dist)
        if len(do_first) > 0:
            id = do_first[0]

        try:
            logger.debug('A : %d, c: %s, t: %s, hits: %s, rem: %s' % (i, id, time.time(), hits, len(do_first)))

            res = get_pems_from_ldap(id)
            logger.info('Success! Found: %s' % id)

            hits += 1
            found.append(id)
            append_to_file(id)
            append_json_to_file(json.dumps(res, cls=AutoJSONEncoder))
            if len(do_first) > 0:
                do_first = do_first[1:]

            time.sleep(slp)

        except Exception as e:
            if 'desc' in e.message and 'LDAP server' in e.message['desc']:
                logger.warning('LDAP server blocked')
                time.sleep(SLEEP_ERR)
                continue

            logger.debug('Exception: %s' % e)
            time.sleep(slp)


if __name__ == '__main__':
    print(main())

