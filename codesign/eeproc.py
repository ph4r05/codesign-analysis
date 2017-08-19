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


class Eeproc(object):
    """
    EE processing
    """
    def __init__(self):
        self.big_nose = BigNose()

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
        Fingerprint
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
        if self.smells_nice(pubnum.n):
            logger.warning('Fingerprint found in the Certificate %s idx %s desc %s  ' % (serial, idx, desc))
            js = collections.OrderedDict()
            js['serial'] = serial
            js['desc'] = desc
            js['id'] = idx
            js['fprint'] = binascii.hexlify(x509.fingerprint(hashes.SHA256()))
            print(json.dumps(js))
            return True
        return False

    def process(self, fnames):
        """
        Processing
        :param fnames:
        :return:
        """
        recs = self.load_processed(fnames)

        num_people = 0
        people_counts = collections.defaultdict(lambda: 0)

        for rec in recs:
            id = int(rec['id'])
            num_people += 1

            for res in rec['res']:
                dn = res['dn']
                certs = res['certs']

                cat_o = self.match_o(dn)
                cat_uo = self.match_ou(dn)
                if cat_uo == AUTH:
                    people_counts[cat_o] += 1

                desc = '%s_%s' % (cat_o, cat_uo)
                for idx, crt_hex in enumerate(certs):
                    bindata = base64.b64decode(crt_hex)
                    totals_obj = self.totals[desc]
                    totals_obj[0] += 1
                    try:
                        cert_pos = self.process_der(bindata, rec, dn, id, desc, idx)
                        if cert_pos:
                            totals_obj[1] += 1
                            logger.warning('Nice DN: %s' % dn)
                    except Exception as e:
                        logger.warning('Exception : %s' % e)

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


def main():
    parser = argparse.ArgumentParser(description='EE processor')

    parser.add_argument('--debug', dest='debug', default=False, action='store_const', const=True,
                        help='Debugging logging')

    parser.add_argument('--fname', dest='fname', default=DEF_JSON_FILE,
                        help='Fname')

    args = parser.parse_args()

    ee = Eeproc()
    ee.process(args.fname)


if __name__ == '__main__':
    print(main())

