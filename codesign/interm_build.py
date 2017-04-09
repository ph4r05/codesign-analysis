#!/usr/bin/env python
# -*- coding: utf-8 -*-

import pkg_resources
import logging
import coloredlogs
import sys
import argparse
import os
import json
import re
import utils
import traceback
import collections
import datetime
import base64
import hashlib
import binascii

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.x509.base import load_pem_x509_certificate, load_der_x509_certificate
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.x509.oid import NameOID
from cryptography.x509.oid import ExtensionOID
from cryptography import x509

from OpenSSL.crypto import load_certificate, load_privatekey, FILETYPE_PEM, FILETYPE_ASN1
from OpenSSL.crypto import X509Store, X509StoreContext
from six import u, b, binary_type, PY3

import base64
import time

import input_obj
import lz4framed
import newline_reader


logger = logging.getLogger(__name__)
coloredlogs.install(level=logging.INFO)


def get_backend(backend=None):
    return default_backend() if backend is None else backend


class IntermediateBuilder(object):
    """
    Builds intermediate CA database from existing datasets
    """

    def __init__(self):
        self.args = None
        self.chain_cert_db = {}

        self.ctr = 0
        self.input_objects = []

        self.assigned_fprints = set()
        self.cur_depth = 1
        self.root_store = X509Store()
        self.cur_store = X509Store()
        self.all_certs = []
        self.interms = {}

    def load_roots(self):
        """
        Loads root certificates
        File downloaded from: https://curl.haxx.se/docs/caextract.html
        :return: 
        """

        resource_package = __name__
        resource_path = '../certs/data/cacert.pem'
        return pkg_resources.resource_string(resource_package, resource_path)

    def roots(self, fname):
        """
        One root file processing
        :param fname: 
        :return: 
        """
        logger.info('Reading file[%02d] %s' % (self.cur_depth, fname))
        with open(fname) as fh:
            for line in fh:
                js = json.loads(line)

                # Already seen in this round
                if js['fprint'] in self.chain_cert_db:
                    continue

                # Already assigned to a trust category
                if js['fprint'] in self.assigned_fprints:
                    continue

                if 'raw' not in js:
                    logger.debug('Raw not present: %s' % js['fprint'])
                    continue

                raw = js['raw']
                rawb = base64.b64decode(raw)
                self.chain_cert_db[js['fprint']] = True

                crypt_cert = load_der_x509_certificate(rawb, get_backend())

                if not utils.try_is_ca(crypt_cert):
                    logger.debug('Cert is not CA: %s' % js['fprint'])
                    continue

                # Verify
                ossl_cert = load_certificate(FILETYPE_ASN1, rawb)
                store_ctx = X509StoreContext(self.cur_store, ossl_cert)
                try:
                    store_ctx.verify_certificate()
                    self.interms[self.cur_depth].append(js)
                    self.assigned_fprints.add(js['fprint'])
                    self.all_certs.append(ossl_cert)

                except:
                    pass

    def work(self):
        """
        Entry point after argument processing.
        :return: 
        """
        roots = self.load_roots()
        logger.info('Roots loaded')

        # 1 - load all CAs, roots from Mozilla.
        roots = roots.split('-----END CERTIFICATE-----')
        for root in roots:
            if len(root.strip()) == 0:
                continue
            try:
                root += '-----END CERTIFICATE-----'
                root_cert = load_certificate(FILETYPE_PEM, root)
                crypt_cert = load_pem_x509_certificate(root, get_backend())
                self.root_store.add_cert(root_cert)
                self.cur_store.add_cert(root_cert)
                self.all_certs.append(root_cert)
                root_fprint = binascii.hexlify(crypt_cert.fingerprint(hashes.SHA256()))
                self.assigned_fprints.add(root_fprint)
                logger.info('Root: %s' % root_fprint)

            except Exception as e:
                logger.error('Exception in processing root cert %s' % e)
                logger.debug(traceback.format_exc())

        logger.info('Roots %s' % self.root_store)

        root_files = []
        for tlsdir in self.args.tlsdir:
            root_files += ([os.path.join(tlsdir, f) for f in os.listdir(tlsdir)
                            if (os.path.isfile(os.path.join(tlsdir, f)) and '.cr.json' in f)])

        # Waves
        for cdepth in range(1, 10):
            logger.info('New depth level: %d' % cdepth)
            self.cur_depth = cdepth
            self.interms[cdepth] = []
            self.chain_cert_db = {}

            for fname in root_files:
                self.roots(fname)

            self.cur_store = X509Store()
            for crt in self.all_certs:
                try:
                    self.cur_store.add_cert(crt)
                except:
                    pass

            ln = len(self.interms[self.cur_depth])
            if ln == 0:
                logger.info('No more certs added, exiting')
                break

            logger.info('New certificates added: %s' % ln)

        # Dump
        for cdepth in range(1, self.cur_depth+1):
            dpath = os.path.join(self.args.data_dir, 'interm-lvl%02d.json' % cdepth)
            with open(dpath, 'w') as fh:
                json.dump(self.interms[cdepth], fh)

    def main(self):
        """
        Main entry point
        :return: 
        """
        parser = argparse.ArgumentParser(description='Censys TLS dataset - generates intermediates CA DB')

        parser.add_argument('--data', dest='data_dir', default='.',
                            help='Data directory output')

        parser.add_argument('--debug', dest='debug', default=False, action='store_const', const=True,
                            help='Debugging logging')

        parser.add_argument('--dry-run', dest='dry_run', default=False, action='store_const', const=True,
                            help='Dry run - no file will be overwritten or deleted')

        parser.add_argument('--tlsdir', dest='tlsdir', nargs=argparse.ZERO_OR_MORE, default=[],
                            help='Directory with TLS results to process')

        self.args = parser.parse_args()

        if self.args.debug:
            coloredlogs.install(level=logging.DEBUG)

        self.work()


def main():
   app = IntermediateBuilder()
   app.main()


if __name__ == '__main__':
    main()


