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
import collections
import argparse
import binascii
from sec_light import BigNose
from cryptography.x509.base import load_der_x509_certificate
from past.builtins import cmp


LDAP_SERVER = "ldap://ldap.sk.ee"

MID = "ESTEID (MOBIIL-ID)"
DIGI = "ESTEID (DIGI-ID)"
IDCARD = "ESTEID"
RESIDENT_DIGI = "ESTEID (DIGI-ID E-RESIDENT)"
RESIDENT_MID = "ESTEID (MOBIIL-ID E-RESIDENT)"

AUTH = "Authentication"
SIGN = "Digital Signature"

DEF_ID_FILE = './eeids.txt'
DEF_JSON_FILE = './eeids.json'


logger = logging.getLogger(__name__)
coloredlogs.install(level=logging.DEBUG)


try:
    import numpy as np
    import matplotlib.pyplot as plt
    PLOT_OK = True
except:
    logger.error('Could not import numpy / matplotlib. Plotting disabled')
    PLOT_OK = False


class ClassifRes(object):
    """
    X509 result
    """
    def __init__(self):
        self.marked = False
        self.n = None
        self.e = None
        self.not_before = None


class Eeproc(object):
    """
    EE processing
    """
    def __init__(self):
        self.big_nose = BigNose()
        self.args = None

        self.totals = collections.defaultdict(lambda: [0, 0])
        self.non_rsa_cats = collections.defaultdict(lambda: 0)
        self.totals_key_types = collections.defaultdict(lambda: 0)
        self.db = []

        self.num_der_certs = 0
        self.num_rsa = 0

        self.m_auth = ('ou=%s,' % AUTH).lower()
        self.m_sign = ('ou=%s,' % SIGN).lower()

        self.m_mid = ('o=%s,' % MID).lower()
        self.m_digi = ('o=%s,' % DIGI).lower()
        self.m_id = ('o=%s,' % IDCARD).lower()
        self.m_res_digi = ('o=%s,' % RESIDENT_DIGI).lower()
        self.m_res_mid = ('o=%s,' % RESIDENT_MID).lower()

    def load_processed(self, fname):
        """
        Load processed
        :param fname:
        :return:
        """
        if not os.path.exists(fname):
            return []
        ret = []
        invser = []
        idset = set()
        dups = 0
        with open(fname) as fh:
            for idx, line in enumerate(fh):
                if len(line) == 0:
                    continue
                line = line.replace('\r\n', '')
                try:
                    js = json.loads(line)
                    id = js['id']
                    if id in idset:
                        dups += 1
                        continue
                    idset.add(id)
                    ret.append(js)
                except Exception as e:
                    serial = line[8:19]
                    invser.append(serial)
                    logger.warning('Parse error, line: %d, %s, e: %s' % (idx, serial, e))
        for x in invser:
            print(x)
        logger.info('Invalid serials: %s, correct: %s, dups: %s' % (len(invser), len(ret), dups))
        return ret

    def get_backend(self, backend=None):
        """
        Default crypto backend
        :param backend:
        :return:
        """
        from cryptography.hazmat.backends import default_backend
        return default_backend() if backend is None else backend

    def smells_nice(self, mod):
        """
        Smelling detection
        :param mod:
        :return:
        """
        return self.big_nose.smells_good(mod)

    def match_ou(self, dn):
        """
        Auth/sign
        :param dn:
        :return:
        """
        dnl = dn.lower()
        if self.m_auth in dnl:
            return AUTH
        elif self.m_sign in dnl:
            return SIGN
        else:
            raise Exception('Unrecognized UO: %s' % dnl)

    def match_o(self, dn):
        """
        digi/mob/est
        :param dn:
        :return:
        """
        dnl = dn.lower()
        if self.m_mid in dnl:
            return MID
        elif self.m_digi in dnl:
            return DIGI
        elif self.m_id in dnl:
            return IDCARD
        elif self.m_res_digi in dnl:
            return RESIDENT_DIGI
        elif self.m_res_mid in dnl:
            return RESIDENT_MID
        else:
            raise Exception('Unrecognized O: %s' % dnl)

    def year_from_serial(self, s):
        """
        Returns year from the serial
        :param s:
        :return:
        """
        s = str(s)
        lst = int(s[1:3])
        d1 = (int(s[0])-1) / 2
        return 1800 + d1 * 100 + lst

    def serial_from_serial(self, s):
        """
        Serial number from the ID
        :param s:
        :return:
        """
        s = str(s)
        return int(s[7:10])

    def process_der(self, data, js, dn, serial, desc, idx):
        """
        DER processing
        :param data:
        :param js:
        :param serial:
        :return:
        """
        from cryptography.x509.base import load_der_x509_certificate
        try:
            x509 = load_der_x509_certificate(data, self.get_backend())
            self.num_der_certs += 1
            return self.process_x509(x509, js=js, dn=dn, serial=serial, desc=desc, idx=idx)

        except Exception as e:
            logger.debug('DER processing failed: %s : %s' % (js['id'], e))
        return None

    def process_x509(self, x509, js, dn, serial, desc, idx):
        """
        Processing parsed X509 certificate
        :param x509:
        :param js:
        :return:
        :rtype: ClassifRes
        """
        if x509 is None:
            return None

        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

        pub = x509.public_key()
        self.totals_key_types[str(pub.__class__)] += 1
        if not isinstance(pub, RSAPublicKey):
            self.non_rsa_cats[desc] += 1
            return None

        self.num_rsa += 1
        pubnum = x509.public_key().public_numbers()

        ret = ClassifRes()
        ret.n = pubnum.n
        ret.e = pubnum.e
        ret.not_before = x509.not_valid_before

        if self.smells_nice(pubnum.n):
            # logger.warning('Good Certificate %s idx %s desc %s  ' % (serial, idx, desc))
            ret.marked = True
            js = collections.OrderedDict()
            js['serial'] = serial
            js['desc'] = desc
            js['id'] = idx
            js['e'] = hex(ret.e)
            js['fprint'] = binascii.hexlify(x509.fingerprint(hashes.SHA256()))[:16]
            print(json.dumps(js))

        return ret

    def strtime(self, x):
        """
        Simple time format
        :param x:
        :return:
        """
        if x is None:
            return x
        return x.strftime('%Y-%m-%d')

    def process(self, args):
        """
        Processing
        :param args:
        :return:
        """
        self.args = args

        fnames = args.fname
        recs = self.load_processed(fnames)

        num_people = 0
        nice_numbers = []
        all_ids = []
        people_counts = collections.defaultdict(lambda: 0)
        classif_fh = open('classif-negative.json', 'w+') if args.classif_negative else None

        for rec in recs:
            id = int(rec['id'])
            all_ids.append(id)
            num_people += 1

            has_auth = False
            has_sign = False
            dn = None
            for res_idx, res in enumerate(rec['res']):
                dn = res['dn']
                certs = res['certs']

                cat_o = self.match_o(dn)
                cat_uo = self.match_ou(dn)
                if cat_uo == AUTH:
                    people_counts[cat_o] += 1

                if cat_o == IDCARD:
                    if cat_uo == AUTH:
                        has_auth = True
                    if cat_uo == SIGN:
                        has_sign = True

                desc = '%s_%s' % (cat_o, cat_uo)
                for idx, crt_hex in enumerate(certs):
                    bindata = base64.b64decode(crt_hex)
                    totals_obj = self.totals[desc]
                    totals_obj[0] += 1
                    try:
                        cert_pos = self.process_der(bindata, rec, dn, id, desc, idx)
                        if cert_pos is None:  # not X509 or RSA
                            continue

                        if cert_pos.marked:
                            totals_obj[1] += 1
                            if cat_uo == AUTH and cat_o == IDCARD:
                                nice_numbers.append(id)
                        elif args.classif_negative:
                            classif_rec = collections.OrderedDict()
                            classif_rec['id'] = '%s%02d%02d' % (id, res_idx, idx)
                            classif_rec['eid'] = id
                            classif_rec['source'] = [dn, self.strtime(cert_pos.not_before)]
                            classif_rec['n'] = hex(cert_pos.n)
                            classif_rec['e'] = hex(cert_pos.e)
                            classif_fh.write(json.dumps(classif_rec) + '\n')
                    except Exception as e:
                        logger.warning('Exception : %s' % e)

            if has_auth != has_sign:
                logger.warning('Not matching auth/sign: %s, %s' % (id, dn))

        if args.classif_negative:
            classif_fh.close()

        # Categories nice / all
        longest = 0
        for o in [IDCARD, DIGI, MID, RESIDENT_DIGI, RESIDENT_MID]:
            for uo in [AUTH, SIGN]:
                ln = len('%s - %s' % (o, uo))
                if ln > longest:
                    longest = ln
        if longest & 1:
            longest += 1

        for o in [IDCARD, DIGI, MID, RESIDENT_DIGI, RESIDENT_MID]:
            for uo in [AUTH, SIGN]:
                cur = self.totals['%s_%s' % (o, uo)]
                pref = '%s - %s' % (o, uo)
                pref_len = len(pref)
                pad = ' .' * ((longest - pref_len)/2)
                if pref_len & 1:
                    pad = ' ' + pad
                print('%s %s %4d / %4d ~ %3.5f %%' % (pref, pad, cur[1], cur[0], cur[1]*100.0/cur[0] if cur[0] > 0 else -1))

        print('\nTotals per user: ')
        print(json.dumps(people_counts, indent=2))

        print('\nTotal key types: ')
        print(json.dumps(self.totals_key_types, indent=2))

        print('\nNon-RSA key occurences: ')
        print(json.dumps(self.non_rsa_cats, indent=2))

        print('\nDER certs: %s, rsa: %s, people: %s' % (self.num_der_certs, self.num_rsa, num_people))

        # y-analysis
        nice_numbers = sorted(list(set(nice_numbers)))
        all_ids = sorted(list(set(all_ids)))
        self.plot_age(all_ids, nice_numbers)

        # serial analysis
        if PLOT_OK and args.plot_serial:
            self.plot_serial(all_ids, nice_numbers)

    def plot_age(self, all_ids, nice_numbers, width=0.35):
        """
        Plot age vs. count
        :param all_years:
        :param nice_years:
        :param width:
        :return:
        """
        nice_years = collections.defaultdict(lambda: 0)
        all_years = collections.defaultdict(lambda: 0)

        for cur in nice_numbers:
            nice_years[self.year_from_serial(cur)] += 1
        for cur in all_ids:
            all_years[self.year_from_serial(cur)] += 1

        xaxis = np.arange(1910, 2020)

        all_y = [all_years[i] for i in xaxis]
        nice_y = [nice_years[i] for i in xaxis]
        fact = 1  # float(sum(all_y)) / sum(nice_y)
        nice_y = [x * fact for x in nice_y]

        fig, ax = plt.subplots()
        rects1 = ax.bar(xaxis, nice_y, width, color='b')
        rects2 = ax.bar(xaxis + width, all_y, width, color='y')
        ax.legend((rects1[0], rects2[0]), ('Nice', 'All'))
        ax.set_ylabel('Count')
        ax.set_title('Year vs. count')
        plt.show()

    def plot_serial(self, all_ids, nice_numbers, width=0.35):
        """
        Plot serial vs. count
        :param all_ids:
        :param nice_numbers:
        :param width:
        :return:
        """
        all_serials = collections.defaultdict(lambda: 0)
        nice_serials = collections.defaultdict(lambda: 0)
        for cur in [self.serial_from_serial(x) for x in all_ids]:
            all_serials[cur] += 1
        for cur in [self.serial_from_serial(x) for x in nice_numbers]:
            nice_serials[cur] += 1

        fig, ax = plt.subplots()
        xaxis = np.arange(0, 1000)

        all_y = [all_serials[i] for i in xaxis]
        nice_y = [nice_serials[i] for i in xaxis]
        fact = float(sum(all_y)) / sum(nice_y)
        nice_y = [x * fact for x in nice_y]

        rects1 = ax.bar(xaxis, nice_y, width, color='b')
        rects2 = ax.bar(xaxis + width, all_y, width, color='y')
        ax.legend((rects1[0], rects2[0]), ('Nice', 'All'))
        ax.set_ylabel('Count')
        ax.set_title('Serials vs. count')
        plt.show()


def main():
    parser = argparse.ArgumentParser(description='EE processor')

    parser.add_argument('--debug', dest='debug', default=False, action='store_const', const=True,
                        help='Debugging logging')

    parser.add_argument('--fname', dest='fname', default=DEF_JSON_FILE,
                        help='Fname')

    parser.add_argument('--plot-serial', dest='plot_serial', default=False, action='store_const', const=True,
                        help='Plot serial vs count')

    parser.add_argument('--classif-negative', dest='classif_negative', default=False, action='store_const', const=True,
                        help='Generate classification JSON from negative occurences')

    args = parser.parse_args()

    ee = Eeproc()
    ee.process(args)


if __name__ == '__main__':
    main()


