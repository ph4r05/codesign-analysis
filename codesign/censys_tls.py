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
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.x509.base import load_pem_x509_certificate, load_der_x509_certificate
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.x509.oid import NameOID
from cryptography.x509.oid import ExtensionOID
from cryptography import x509
import base64

import input_obj
import lz4framed
import newline_reader


logger = logging.getLogger(__name__)
coloredlogs.install(level=logging.INFO)


def get_backend(backend=None):
    return default_backend() if backend is None else backend


class MyCrt(object):
    """
    My certificate record
    """
    def __init__(self, *args, **kwargs):
        pass


class CensysTls(object):
    """
    Downloading & processing of the Censys data
    """

    def __init__(self):
        self.args = None
        self.chain_cert_db = {}

        self.link_idx_offset = 0
        self.input_objects = []

        # Current state
        self.not_tls = 0
        self.not_cert_ok = 0
        self.not_chain_ok = 0
        self.not_parsed = 0
        self.not_rsa = 0

        self.ctr = 0
        self.chain_ctr = 0
        self.processor = None
        self.file_leafs_fh = None
        self.file_roots_fh = None

    def load_roots(self):
        """
        Loads root certificates
        File downloaded from: https://curl.haxx.se/docs/caextract.html
        :return: 
        """

        resource_package = __name__
        resource_path = 'data/cacert.pem'
        return pkg_resources.resource_string(resource_package, resource_path)

    def process(self):
        """
        Process all input objects
        :return: 
        """
        for iobj in self.input_objects:
            try:
                self.process_iobj(iobj)
            except Exception as e:
                logger.error('Exception when processing IOBJ: %s, %s' % (iobj, e))
                logger.debug(traceback.format_exc())

    def iobj_name(self, iobj):
        """
        Tries to determine experiment name from the input object
        example: p6p0lbheekv0cwdz-443-https-tls-full_ipv4-20170323T023003-zgrab-log.log.lz4
        :param iobj: 
        :return: 
        """
        name = str(iobj)
        try:
            name = os.path.basename(name)
            match = re.match(r'^([a-zA-Z0-9]+)-443-', name)

            if match:
                sub = match.group(1)
                name = name.replace(sub + '-', '')

        except Exception as e:
            logger.error('Error in determining experiment name %s' % e)
            logger.info(traceback.format_exc())

        return name

    def get_finish_file(self, name):
        """
        Returns path to the finish indicator file
        :param name: 
        :return: 
        """
        return os.path.join(self.args.data_dir, name + '.finished')

    def get_classification_leafs(self, name):
        """
        Returns path to the json classification file for leafs 
        :param name: 
        :return: 
        """
        return os.path.join(self.args.data_dir, name + '.cl.json')

    def get_classification_roots(self, name):
        """
        Returns path to the json classification file for leafs 
        :param name: 
        :return: 
        """
        return os.path.join(self.args.data_dir, name + '.cr.json')

    def process_iobj(self, iobj):
        """
        Processing
        :param iobj: 
        :return: 
        """
        input_name = self.iobj_name(iobj)
        logger.info('Processing: %s' % input_name)

        finish_file = self.get_finish_file(input_name)
        if os.path.exists(finish_file):
            logger.info('Finish indicator file exists, skipping: %s' % finish_file)
            return

        file_leafs = self.get_classification_leafs(input_name)
        file_roots = self.get_classification_roots(input_name)
        utils.safely_remove(file_leafs)
        utils.safely_remove(file_roots)
        self.file_leafs_fh = utils.safe_open(file_leafs, mode='w', chmod=0o644)
        self.file_roots_fh = utils.safe_open(file_roots, mode='w', chmod=0o644)

        self.processor = newline_reader.NewlineReader(is_json=True)
        with iobj:
            handle = iobj.handle()
            name = str(iobj)

            if name.endswith('lz4'):
                handle = lz4framed.Decompressor(handle)

            for idx, record in self.processor.process(handle):
                try:
                    self.process_record(idx, record)
                except Exception as e:
                    logger.error('Exception in processing %d: %s' % (self.ctr, e))
                    logger.debug(traceback.format_exc())

                self.ctr += 1

            logger.info('Total: %d' % self.ctr)
            logger.info('Total_chain: %d' % self.chain_ctr)
            logger.info('Not tls: %d' % self.not_tls)
            logger.info('Not cert ok: %d' % self.not_cert_ok)
            logger.info('Not chain ok: %d' % self.not_chain_ok)
            logger.info('Not parsed: %d' % self.not_parsed)
            logger.info('Not rsa: %d' % self.not_rsa)

        logger.info('Processed: %s' % iobj)
        self.file_leafs_fh.close()
        self.file_roots_fh.close()
        utils.try_touch(finish_file)

    def is_record_tls(self, record):
        """
        Returns true if contains server_certificates
        :param record: 
        :return: 
        """
        if 'data' not in record:
            # logger.info('No data for %s' % domain)
            return False

        if 'tls' not in record['data']:
            # logger.info('No tls for %s' % domain)
            return False

        if 'server_certificates' not in record['data']['tls']:
            # logger.info('No server_certificates for %s' % domain)
            return False

        return True

    def fill_rsa_ne(self, ret, parsed):
        """
        Extracts mod, exponent from parsed
        :param ret: 
        :param parsed: 
        :return: 
        """
        mod16 = base64.b16encode(base64.b64decode(parsed['subject_key_info']['rsa_public_key']['modulus']))
        ret['n'] = '0x%s' % mod16
        ret['e'] = hex(int(parsed['subject_key_info']['rsa_public_key']['exponent']))

    def fill_cn_src(self, ret, parsed):
        """
        Fillts in CN, Source
        :param ret: 
        :param parsed: 
        :return: 
        """
        ret['cn'] = utils.defvalkeys(parsed, ['subject', 'common_name', 0])
        not_before = parsed['validity']['start']
        not_before = not_before[:not_before.find('T')]
        ret['source'] = [ret['cn'], not_before]

    def process_record(self, idx, record):
        """
        Current record
        {"e":"0x10001","count":1,"source":["COMMON_NAME","NOT_BEFORE_2010-11-19"],
        "id":32000000,"cn":"COMMON_NAME","n":"0x...","timestamp":1475342704760}

        :param idx: 
        :param record: 
        :return: 
        """
        ip = utils.defvalkey(record, 'ip')
        domain = utils.defvalkey(record, 'domain')
        timestamp_fmt = utils.defvalkey(record, 'timestamp')

        if not self.is_record_tls(record):
            self.not_tls += 1
            return

        server_cert = record['data']['tls']['server_certificates']
        if 'validation' not in server_cert or 'certificate' not in server_cert:
            self.not_cert_ok += 1
            return

        trusted = utils.defvalkey(server_cert['validation'], 'browser_trusted')
        matches = utils.defvalkey(server_cert['validation'], 'matches_domain')
        cert_obj = server_cert['certificate']

        if 'parsed' not in cert_obj:
            self.not_parsed += 1
            return

        parsed = cert_obj['parsed']
        try:
            ret = collections.OrderedDict()
            if parsed['subject_key_info']['key_algorithm']['name'].lower() != 'rsa':
                self.not_rsa += 1
                return

            ret['id'] = self.ctr
            ret['ip'] = ip
            ret['dom'] = domain
            ret['count'] = 1

            tstamp = utils.try_parse_timestamp(timestamp_fmt)
            ret['timestamp'] = utils.unix_time(tstamp)
            ret['trust'] = trusted
            ret['match'] = matches
            ret['valid'] = utils.defvalkeys(parsed, ['signature', 'valid'])
            ret['ssign'] = utils.defvalkeys(parsed, ['signature', 'self_signed'])
            self.fill_cn_src(ret, parsed)
            self.fill_rsa_ne(ret, parsed)
            ret['chains'] = self.process_roots(idx, record, server_cert)

            self.file_leafs_fh.write(json.dumps(ret) + '\n')

        except Exception as e:
            logger.warning('Certificate processing error %s : %s' % (self.ctr, e))
            logger.debug(traceback.format_exc())
            self.not_cert_ok += 1

    def process_roots(self, idx, record, server_cert):
        """
        Process root certificates
        :param idx: 
        :param record: 
        :param server_cert: 
        :return: 
        """
        chains_ctr = []
        try:
            if 'chain' not in server_cert:
                return chains_ctr

            for cert in server_cert['chain']:
                self.chain_ctr += 1
                if 'parsed' not in cert:
                    continue

                parsed = cert['parsed']
                fprint = parsed['fingerprint_sha256']
                if fprint in self.chain_cert_db:
                    chains_ctr.append(self.chain_cert_db[fprint])
                    continue

                ret = collections.OrderedDict()
                if parsed['subject_key_info']['key_algorithm']['name'].lower() != 'rsa':
                    self.not_rsa += 1
                    return

                ret['id'] = self.chain_ctr
                ret['count'] = 1
                ret['chain'] = 1
                ret['valid'] = utils.defvalkeys(parsed, ['signature', 'valid'])
                ret['ssign'] = utils.defvalkeys(parsed, ['signature', 'self_signed'])
                ret['fprint'] = fprint
                self.fill_cn_src(ret, parsed)
                self.fill_rsa_ne(ret, parsed)
                self.file_roots_fh.write(json.dumps(ret) + '\n')
                self.chain_cert_db[fprint] = self.chain_ctr
                chains_ctr.append(self.chain_ctr)

        except Exception as e:
            logger.warning('Chain processing error %s : %s' % (self.chain_ctr, e))
            logger.debug(traceback.format_exc())
            self.not_chain_ok += 1

        return chains_ctr

    def work(self):
        """
        Entry point after argument processing.
        :return: 
        """

        # Build input objects
        for file_name in self.args.file:
            iobj = input_obj.FileInputObject(file_name, rec=None)
            self.input_objects.append(iobj)

        for url in self.args.url:
            iobj = input_obj.LinkInputObject(url, rec=None)
            self.input_objects.append(iobj)

        link_indices = None
        if len(self.args.link_idx) > 0:
            link_indices = set([int(x) for x in self.args.link_idx])

        for link_file in self.args.link_file:
            with open(link_file, 'r') as fh:
                data = fh.read()
                js = json.loads(data)
                datasets = js['data']

            for dataset in datasets:
                did = dataset['id']
                if link_indices is not None and did not in link_indices:
                    continue

                iobj = input_obj.LinkInputObject(dataset['files']['zgrab-results.json.lz4']['href'], rec=dataset)
                self.input_objects.append(iobj)

        # Process all input objects
        self.process()

    def main(self):
        """
        Main entry point
        :return: 
        """
        parser = argparse.ArgumentParser(description='Censys TLS dataset processor')

        parser.add_argument('--data', dest='data_dir', default='.',
                            help='Data directory output')

        parser.add_argument('--scratch', dest='scratch_dir', default='.',
                            help='Scratch directory output')

        parser.add_argument('-t', dest='threads', default=1,
                            help='Number of download threads to use')

        parser.add_argument('--debug', dest='debug', default=False, action='store_const', const=True,
                            help='Debugging logging')

        parser.add_argument('--link-file', dest='link_file', nargs=argparse.ZERO_OR_MORE, default=[],
                            help='JSON file generated by censys_links.py')

        parser.add_argument('--link-idx', dest='link_idx', nargs=argparse.ZERO_OR_MORE, default=[],
                            help='Link indices to process')

        parser.add_argument('--file', dest='file', nargs=argparse.ZERO_OR_MORE, default=[],
                            help='LZ4 files to process')

        parser.add_argument('--url', dest='url', nargs=argparse.ZERO_OR_MORE, default=[],
                            help='LZ4 URL to process')

        self.args = parser.parse_args()

        if self.args.debug:
            coloredlogs.install(level=logging.DEBUG)

        self.work()


def main():
   app = CensysTls()
   app.main()


if __name__ == '__main__':
    main()


