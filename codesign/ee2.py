#!/usr/bin/env python
# -*- coding: utf-8 -*-

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
DEF_ID_FILE = 'eeids'
DEF_JSON_FILE = 'eeids'

# SERIALS = sorted([int(str(x)[7:10]) for x in ISIKUKOODS])
SERIALS = [1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 4, 4, 4, 4, 4, 5, 5, 5, 5, 6, 6, 7, 7, 7, 7, 8, 8, 8, 8, 9, 9, 9, 9, 9, 10, 10, 10, 10, 10, 10, 10, 10, 11, 11, 11, 11, 11, 12, 12, 13, 14, 14, 15, 15, 15, 16, 17, 21, 21, 21, 21, 22, 22, 22, 23, 23, 23, 23, 24, 24, 24, 24, 25, 25, 25, 25, 25, 26, 26, 26, 26, 27, 27, 27, 27, 27, 27, 28, 29, 29, 29, 29, 30, 31, 32, 32, 33, 33, 34, 34, 35, 36, 38, 38, 39, 90, 202, 222, 223, 225, 271, 271, 271, 272, 272, 272, 273, 273, 273, 273, 273, 274, 279, 371, 421, 421, 423, 423, 423, 423, 493, 521, 521, 521, 521, 521, 524, 571, 571, 572, 601, 601, 601, 601, 601, 602, 602, 602, 602, 602, 604, 651, 651, 651, 651, 652, 652, 654]


_ = lambda x: x  # please copypaste from lib/libldap.py
logger = logging.getLogger(__name__)

coloredlogs.CHROOT_FILES = []
coloredlogs.install(level=logging.DEBUG, use_chroot=False)


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


class EeFetch(object):
    def __init__(self):
        self.args = None
        self.hostname = socket.gethostname()
        self.id_file = DEF_ID_FILE + '.txt'
        self.json_file = DEF_JSON_FILE + '.json'

    def get_pems_from_ldap(self, idcode, cert_type=None, chip_type=None):
        """
        Fetches the certificate(s) of the idcode owner from SK LDAP.
        """
        try:
            import ldap
        except:
            logger.error('Could not import ldap. Try: pip install python-ldap')
            sys.exit(1)

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
        js['time'] = time.time()
        js['pid'] = os.getpid()
        js['host'] = self.hostname
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
        #return [EeFetch.get_pem_from_der(x) for x in result[1][0][1]['userCertificate;binary']]

    @staticmethod
    def get_pem_from_der(self, der):
        """
        Converts DER certificate to PEM.
        """
        return "\n".join(("-----BEGIN CERTIFICATE-----",
                          "\n".join(textwrap.wrap(base64.b64encode(der), 64)),
                          "-----END CERTIFICATE-----",))

    @staticmethod
    def lower_strip(x):
        """
        Lower & strip
        :param x:
        :return:
        """
        if x is None:
            return x

        x = str(x)
        try:
            return x.strip().lower()
        except:
            return x

    @staticmethod
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

    @staticmethod
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

    @staticmethod
    def build_serial_pms(ex):
        """
        Probability mass function on serials from collected samples
        :return:
        """
        hists = sorted(SERIALS)
        pms = [0.005 if not ex else 1] * 1000  # serial pms, baseline score

        # significance groups
        EeFetch.add_score(pms, range(1, 40), 100 if not ex else 50)
        EeFetch.add_score(pms, range(1, 99), 5 if not ex else 25)

        if ex:
            EeFetch.add_score(pms, range(200, 300), 25)
            EeFetch.add_score(pms, range(400, 500), 25)
            EeFetch.add_score(pms, range(500, 600), 25)
            EeFetch.add_score(pms, range(600, 700), 25)

        else:
            EeFetch.add_score(pms, range(200, 230), 6)
            EeFetch.add_score(pms, range(270, 280), 15)
            EeFetch.add_score(pms, range(420, 430), 5)
            EeFetch.add_score(pms, range(520, 530), 8)
            EeFetch.add_score(pms, range(600, 610), 15)
            EeFetch.add_score(pms, range(650, 660), 11)

        # collected data - adding points
        # give away another 100 points in total
        total = len(hists)
        one_pt = 150.0 / float(total)
        for k, g in itertools.groupby(hists, lambda x: x):
            pms[k] += one_pt * len(list(g))

        # normalize for use as pms
        pmsn = EeFetch.normalize(pms)
        return pmsn

    @staticmethod
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

    @staticmethod
    def plot_pms(dist):
        """
        Plots PMF of the distribution
        :param dist:
        :return:
        """
        import matplotlib.pyplot as plt
        import numpy as np

        xk = np.arange(1000)
        fig, ax = plt.subplots(1, 1)
        ax.bar(xk, dist.pmf(xk))
        # ax.plot(xk, dist.pmf(xk), 'ro', ms=12, mec='r')
        # ax.vlines(xk, 0, dist.pmf(xk), colors='r', lw=4)
        plt.show()

    @staticmethod
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

    @staticmethod
    def random_isikukood(serial_dist=None):
        """
        Generates random personal code / isikukood
        :return:
        """
        # pick those likely alive and already having IDs
        year = random.randint(1910, 2017)
        century = (year - 1800) / 100

        sex = random.randint(1, 2)  # 1,2 for 18xx | 3,4 for 19xx | 5,6 for 20xx
        d1 = sex + 2*century

        # generate random day & month in that year - ordinals
        minord = datetime.date(year=year, month=1, day=1).toordinal()
        maxord = datetime.date(year=year, month=12, day=31).toordinal()
        randord = random.randint(minord, maxord)
        rnddate = datetime.date.fromordinal(randord)

        # serial = random.randint(0, 999)  # general serial space, not very effective though
        serial = random.randint(1, 40)  # small serials, gives 1:3 success rate
        if serial_dist is not None:
            serial = serial_dist.rvs()

        code = '%d%02d%02d%02d%03d' % (d1, year % 100, rnddate.month, rnddate.day, serial)
        return code + EeFetch.control_nr(code)

    def init_file_names(self):
        """
        Sets file names properly
        :return:
        """
        self.id_file = os.path.join(self.args.outputdir, DEF_ID_FILE)
        self.json_file = os.path.join(self.args.outputdir, DEF_JSON_FILE)
        pid = os.getpid()

        if self.args.add_id:
            timerand = int(time.time()*1000) % 1000
            self.id_file = '%s_%s_%05d_%03d.txt' % (self.id_file, self.hostname, pid, timerand)
            self.json_file = '%s_%s_%05d_%03d.json' % (self.json_file, self.hostname, pid, timerand)
        else:
            self.id_file += '.txt'
            self.json_file += '.json'

        logger.info('ID file: %s @ %s.%s' % (self.id_file, self.hostname, pid))
        logger.info('JS file: %s @ %s.%s' % (self.json_file, self.hostname, pid))

    def append_to_file(self, id):
        with open(self.id_file, 'a+') as fh:
            fh.write('%s\n' % id)
            fh.flush()

    def append_json_to_file(self, data):
        with open(self.json_file, 'a+') as fh:
            fh.write('%s\n' % data)
            fh.flush()

    def load_idxs(self):
        if not os.path.exists(self.id_file):
            return []
        with open(self.id_file) as fh:
            return [int(x) for x in fh.readlines() if len(x.strip()) > 0]

    def load_processed(self):
        if not os.path.exists(self.json_file):
            return []
        ret = []
        with open(self.json_file) as fh:
            lines = fh.readlines()
            for l in [x.strip() for x in lines if len(x.strip()) > 0]:
                js = json.loads(l)
                ret.append(int(js['id']))
        return ret

    def main(self):
        """
        Main entry method
        :return:
        """
        parser = argparse.ArgumentParser(description='EE fetcher')

        parser.add_argument('--debug', dest='debug', default=False, action='store_const', const=True,
                            help='Debugging logging')

        parser.add_argument('--pms', dest='pms', default=False, action='store_const', const=True,
                            help='Use observed PMS')

        parser.add_argument('--pms-ex', dest='pms_ex', default=False, action='store_const', const=True,
                            help='Use observed PMS - extended')

        parser.add_argument('--output-dir', dest='outputdir', default='.',
                            help='Dir with output data')

        parser.add_argument('--add-id', dest='add_id', default=False, action='store_const', const=True,
                            help='Adds current process ID to the file name')

        parser.add_argument('--one-bulk', dest='one_bulk', default=False, action='store_const', const=True,
                            help='one bulk processing - exit on connect problem')

        parser.add_argument('--pms-plot', dest='pms_plot', default=False, action='store_const', const=True,
                            help='Plot PMS only and exit')

        parser.add_argument('--pause', dest='pause', default=SLEEP_OK, type=int,
                            help='Sleep after success query')

        parser.add_argument('--pause-ex', dest='pause_ex', default=SLEEP_ERR, type=int,
                            help='Sleep after error query')

        parser.add_argument('--max-walltime', dest='max_walltime', default=None, type=int,
                            help='Maximum walltime')

        self.args = parser.parse_args()
        slp = self.args.pause
        slp_err = self.args.pause_ex
        hits = 0
        time_start = time.time()
        found = []

        self.init_file_names()
        if self.args.add_id:
            time.sleep(random.uniform(0, slp))

        loaded = set(self.load_processed())
        do_first = sorted(list(set([x for x in self.load_idxs() if x not in loaded])))
        logger.info('Non-processed: %s' % len(do_first))

        pms = EeFetch.build_serial_pms(self.args.pms_ex)
        cust_dist = EeFetch.build_serial_dist(pms)

        dist = cust_dist if self.args.pms or self.args.pms_ex or self.args.pms_plot else None
        if dist is not None:
            logger.info('Using custom PMS')
        if self.args.pms_ex:
            logger.info('Using extended PMS')

        if self.args.pms_plot:
            EeFetch.plot_pms(dist)
            return

        for i in range(50000):
            id = EeFetch.random_isikukood(dist)
            if len(do_first) > 0:
                id = do_first[0]

            try:
                if self.args.max_walltime and (time.time() - time_start) > self.args.max_walltime:
                    logger.info('Terminating, max wall time reached')
                    return

                logger.debug('A : %d, c: %s, t: %s, hits: %s, rem: %s' % (i, id, time.time(), hits, len(do_first)))

                res = self.get_pems_from_ldap(id)
                logger.info('Success! Found: %s' % id)

                hits += 1
                found.append(id)
                self.append_to_file(id)
                self.append_json_to_file(json.dumps(res, cls=AutoJSONEncoder))
                if len(do_first) > 0:
                    do_first = do_first[1:]

                time.sleep(slp)

            except Exception as e:
                blocked = 'desc' in e.message and 'LDAP server' in e.message['desc']
                unknown = 'no results' not in EeFetch.lower_strip(e.message)

                if blocked or unknown:
                    if blocked:
                        logger.warning('LDAP server blocked @ %s' % self.hostname)
                    else:
                        logger.warning('Exception: %s [%s]' % (e, e.message))

                    if self.args.one_bulk:
                        logger.info('One bulk, terminating')
                        return

                    if self.args.max_walltime and ((time.time() - time_start) + slp_err) > self.args.max_walltime:
                        logger.info('Terminating, waiting would exceed walltime')
                        return

                    time.sleep(slp_err)
                    continue

                if self.args.add_id:
                    time.sleep(random.uniform(slp*0.95, slp*1.05))
                else:
                    time.sleep(slp)


if __name__ == '__main__':
    ee = EeFetch()
    print(ee.main())

