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
import time

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


class DecompressorCheckpoint(object):
    """
    Represents simple point in the data stream for random access read.
    """
    def __init__(self, pos, crcctx=None, *args, **kwargs):
        self.pos = pos
        self.crcctx = crcctx

    def to_json(self):
        js = collections.OrderedDict()
        js['pos'] = self.pos
        js['crcctx'] = base64.b64encode(self.crcctx) if self.crcctx is not None else None
        return js


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

        self.loaded_checkpoint = None
        self.read_data = 0
        self.last_report = 0
        self.ctr = 0
        self.chain_ctr = 0
        self.cur_state_file = None
        self.cur_decompressor = None
        self.processor = None
        self.file_leafs_fh = None
        self.file_roots_fh = None
        self.last_record_resumed = None
        self.decompressor_checkpoints = {}

    def load_roots(self):
        """
        Loads root certificates
        File downloaded from: https://curl.haxx.se/docs/caextract.html
        :return: 
        """

        resource_package = __name__
        resource_path = 'data/cacert.pem'
        return pkg_resources.resource_string(resource_package, resource_path)

    def is_dry(self):
        """
        Returns true if dry run
        :return: 
        """
        return self.args.dry_run

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
                logger.info('Progress: %s' % self.ctr)
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

    def get_state_file(self, name):
        """
        Returns path to the state file with progress & resumption data
        :param name: 
        :return: 
        """
        return os.path.join(self.args.data_dir, name + '.state.json')

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

    def continue_roots(self):
        """
        Read roots line by line, build chain database.
        Find the last valid record, remove on that one.
        :return: 
        """

        pos = 0
        invalid_record = False

        for line in self.file_roots_fh:
            ln = len(line)
            try:
                js = json.loads(line)
                self.chain_cert_db[js['fprint']] = js['id']
                self.chain_ctr = max(self.chain_ctr, js['id'])
                pos += ln

            except Exception as e:
                invalid_record = True
                break

        logger.info('Operation resumed at chain ctr: %s, total chain records: %s'
                    % (self.chain_ctr, len(self.chain_cert_db)))

        if invalid_record:
            logger.info('Roots: Invalid record detected, position: %s' % pos)

            if not self.is_dry():
                self.file_roots_fh.seek(pos)
                self.file_roots_fh.truncate()
                self.file_roots_fh.flush()

    def continue_leafs(self, name):
        """
        Continues processing of the leafs.
        Finds the last record - returns this also.
        Truncates the rest of the file.
        :param name: 
        :return: last record loaded
        """
        fsize = os.path.getsize(name)
        pos = 0

        # If file is too big try to skip 10 MB before end
        if fsize > 1024*1024*20:
            pos = fsize - 1024*1024*10
            logger.info('Leafs file too big: %s, skipping to %s' % (fsize, pos))

            self.file_leafs_fh.seek(pos)
            x = self.file_leafs_fh.next()  # skip unfinished record
            pos += len(x)

        invalid_record = False
        last_record = None
        for line in self.file_leafs_fh:
            ln = len(line)
            try:
                last_record = json.loads(line)
                self.ctr = max(self.ctr, last_record['id'])
                pos += ln

            except Exception as e:
                invalid_record = True
                break

        logger.info('Operation resumed at leaf ctr: %s, last ip: %s'
                    % (self.ctr, utils.defvalkey(last_record, 'ip')))

        if invalid_record:
            logger.info('Leaf: Invalid record detected, position: %s' % pos)

            if not self.is_dry():
                self.file_leafs_fh.seek(pos)
                self.file_leafs_fh.truncate()
                self.file_leafs_fh.flush()

        return last_record

    def store_checkpoint(self, iobj, idx=None, resume_idx=None, resume_token=None):
        """
        Stores checkpoint for the current input object
        :param iobj: 
        :param idx: 
        :param resume_idx: 
        :param resume_token: 
        :return: 
        """
        state_file = self.cur_state_file
        if self.is_dry():
            state_file += '.dry'

        input_name = self.iobj_name(iobj)

        js = collections.OrderedDict()
        js['iobj_name'] = input_name
        js['time'] = time.time()
        js['read_raw'] = self.read_data
        js['block_idx'] = idx
        js['resume_idx'] = resume_idx
        js['resume_token'] = resume_token

        # Serialize input object state
        js['iobj'] = iobj.to_state()
        js['loaded_checkpoint'] = self.loaded_checkpoint

        # New decompressor checkpoint for random access read
        if self.cur_decompressor is not None and self.cur_decompressor.last_read_aligned:
            total_read_dec = self.cur_decompressor.data_read
            crc_ctx = lz4framed.marshal_decompression_checksum_context(self.cur_decompressor.ctx)
            self.decompressor_checkpoints[total_read_dec] = DecompressorCheckpoint(total_read_dec, crc_ctx)

        js['dec_checks'] = [x.to_json() for x in self.decompressor_checkpoints.values()]

        # Serialize state of the decompressor
        if self.cur_decompressor is not None:
            try:
                decctx = lz4framed.marshal_decompression_context(self.cur_decompressor.ctx)
                logger.debug('Decompressor state marshalled, size: %s kB' % (len(decctx)/1024.0))
                decctx_str = base64.b16encode(decctx)
                js['dec_ctx'] = decctx_str
            except Exception as e:
                logger.error('Exception when storing decompressor state: %s' % e)
                logger.warning(traceback.format_exc())

        utils.flush_json(js, state_file)

    def restore_checkpoint(self, iobj):
        """
        Tries to restore the checkpoint
        :param iobj: 
        :return: 
        """
        state_file = self.cur_state_file
        input_name = self.iobj_name(iobj)
        if not os.path.exists(state_file):
            logger.info('No checkpoint found for %s' % input_name)
            return

        logger.info('Trying to restore the checkpoint %s for %s' % (state_file, input_name))

        # backup checkpoint so it is not overwritten by invalid state
        utils.file_backup(state_file)

        with open(state_file, 'r') as fh:
            js = json.load(fh)
            if 'read_raw' not in js or 'iobj' not in js or 'data_read' not in js['iobj']:
                raise ValueError('State file is invalid')

            offset = js['iobj']['data_read'] + utils.intval(js['iobj']['start_offset'])
            self.read_data = js['read_raw']

            logger.info('Restoring checkpoint, offset: %s, read_data: %s' % (offset, self.read_data))
            iobj.start_offset = offset

            self.loaded_checkpoint = js

            if 'dec_checks' in js:
                self.decompressor_checkpoints = {x['pos']: DecompressorCheckpoint(x['pos'], x['crcctx'])
                                                 for x in js['dec_checks']}

            if self.cur_decompressor is not None and 'dec_ctx' in js:
                logger.info('Restoring decompressor state')
                decctx_str = base64.b16decode(js['dec_ctx'])
                decctx = lz4framed.unmarshal_decompression_context(decctx_str)
                self.cur_decompressor.setctx(decctx)
                self.loaded_checkpoint['dec_ctx'] = None

        logger.info('Decompressor checkpoint restored for %s' % input_name)

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

        self.cur_decompressor = None
        self.cur_state_file = self.get_state_file(input_name)
        file_leafs = self.get_classification_leafs(input_name)
        file_roots = self.get_classification_roots(input_name)
        self.last_record_resumed = None

        if not self.is_dry() and not self.args.continue1:
            utils.safely_remove(file_leafs)
            utils.safely_remove(file_roots)
            self.file_leafs_fh = utils.safe_open(file_leafs, mode='w', chmod=0o644)
            self.file_roots_fh = utils.safe_open(file_roots, mode='w', chmod=0o644)

        elif self.args.continue1:
            logger.info('Continuing with the started files')
            self.file_leafs_fh = open(file_leafs, mode='r+' if not self.is_dry() else 'r')
            self.file_roots_fh = open(file_roots, mode='r+' if not self.is_dry() else 'r')
            self.continue_roots()
            self.last_record_resumed = self.continue_leafs(file_leafs)

        self.processor = newline_reader.NewlineReader(is_json=False)
        handle = iobj
        name = str(iobj)

        if name.endswith('lz4'):
            self.cur_decompressor = lz4framed.Decompressor(handle)
            handle = self.cur_decompressor

        if self.args.continue1:
            self.restore_checkpoint(iobj)

        with iobj:
            resume_token_found = False
            resume_token = None
            resume_idx = 0
            if self.last_record_resumed is not None and 'ip' in self.last_record_resumed:
                resume_token = ('{"ip":"%s",' % self.last_record_resumed['ip']).encode('utf-8')
                resume_idx = int(self.last_record_resumed['id']) - 100
                logger.info('Resume token built: %s' % resume_token)
                logger.info('Resume index: %d, original index: %s' % (resume_idx, self.last_record_resumed['id']))

            record_ctr = -1
            for idx, record in self.processor.process(handle):
                try:
                    record_ctr += 1
                    self.read_data += len(record)
                    if self.read_data - self.last_report >= 1024*1024*1024:
                        logger.info('...progress: %s GB, idx: %s, pos: %s, mem: %04.8f MB'
                                    % (self.read_data/1024.0/1024.0/1024.0, idx, self.read_data,
                                       utils.get_mem_usage()/1024.0/1024.0))

                        self.last_report = self.read_data
                        self.store_checkpoint(iobj=iobj, idx=idx, resume_idx=resume_idx, resume_token=resume_token)

                    if resume_token is not None and not resume_token_found:
                        if record_ctr < resume_idx:
                            continue

                        if record.startswith(resume_token):
                            resume_token_found = True
                            logger.info('Resume token found, idx: %s, pos: %s, rec: %s'
                                        % (idx, self.read_data, record))
                            continue

                        else:
                            continue

                    js = json.loads(record)
                    self.process_record(idx, js)

                except Exception as e:
                    logger.error('Exception in processing %d: %s' % (self.ctr, e))
                    logger.debug(traceback.format_exc())
                    logger.debug(record)

                self.ctr += 1

            logger.info('Total: %d' % self.ctr)
            logger.info('Total_chain: %d' % self.chain_ctr)
            logger.info('Not tls: %d' % self.not_tls)
            logger.info('Not cert ok: %d' % self.not_cert_ok)
            logger.info('Not chain ok: %d' % self.not_chain_ok)
            logger.info('Not parsed: %d' % self.not_parsed)
            logger.info('Not rsa: %d' % self.not_rsa)

        logger.info('Processed: %s' % iobj)
        if not self.is_dry():
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

        # Process chains anyway as we may be interested in them even though the server is not RSA
        chains_roots = self.process_roots(idx, record, server_cert)

        # Process server cert
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
            ret['count'] = 1
            utils.set_nonempty(ret, 'dom', domain)

            tstamp = utils.try_parse_timestamp(timestamp_fmt)
            ret['timestamp'] = utils.unix_time(tstamp)
            utils.set_nonempty(ret, 'trust', trusted)
            utils.set_nonempty(ret, 'match', matches)
            utils.set_nonempty(ret, 'valid', utils.defvalkeys(parsed, ['signature', 'valid']))
            utils.set_nonempty(ret, 'ssign', utils.defvalkeys(parsed, ['signature', 'self_signed']))

            self.fill_cn_src(ret, parsed)
            self.fill_rsa_ne(ret, parsed)
            ret['chains'] = chains_roots

            if not self.is_dry():
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
                if ret['valid']:
                    ret['raw'] = fprint

                if not self.is_dry():
                    self.file_roots_fh.write(json.dumps(ret) + '\n')

                self.chain_cert_db[fprint] = self.chain_ctr
                chains_ctr.append(self.chain_ctr)

        except Exception as e:
            logger.warning('Chain processing error %s : %s' % (self.chain_ctr, e))
            logger.debug(traceback.format_exc())
            self.not_chain_ok += 1

        return chains_ctr

    def _build_link_object(self, url, rec):
        """
        Builds a link object to be processed
        :param url: 
        :param rec: 
        :return: 
        """
        return input_obj.ReconnectingLinkInputObject(url, rec=rec, timeout=5*60, max_reconnects=1000)

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
            iobj = self._build_link_object(url=url, rec=None)
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

                iobj = self._build_link_object(url=dataset['files']['zgrab-results.json.lz4']['href'], rec=dataset)
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

        parser.add_argument('--dry-run', dest='dry_run', default=False, action='store_const', const=True,
                            help='Dry run - no file will be overwritten or deleted')

        parser.add_argument('--continue', dest='continue1', default=False, action='store_const', const=True,
                            help='Continue from the previous attempt')

        parser.add_argument('--continue-frac', dest='continue_frac', default=None, type=float,
                            help='Fraction of the file to start reading from')

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


