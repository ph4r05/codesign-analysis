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
from trace_logger import Tracelogger
from sec import Fprinter

logger = logging.getLogger(__name__)
coloredlogs.install(level=logging.INFO)


def get_backend(backend=None):
    return default_backend() if backend is None else backend


class DecompressorCheckpoint(object):
    """
    Represents simple point in the data stream for random access read.
    """

    def __init__(self, pos, rec_pos=None, plain_pos=None, ctx=None, *args, **kwargs):
        """
        New checkpoint    
        :param pos: position in the compressed stream (on the input) - seekable position for random access.
        :param rec_pos: position in the decompressed stream, newline separated. record boundary
        :param plain_pos: position in the decompressed stream, decompressed chunk >= rec_pos
        :param ctx: decompressor context
        :param args: 
        :param kwargs: 
        """
        self.pos = pos
        self.rec_pos = rec_pos
        self.plain_pos = plain_pos
        self.ctx = ctx

    def to_json(self):
        js = collections.OrderedDict()
        js['pos'] = self.pos
        js['rec_pos'] = self.rec_pos
        js['plain_pos'] = self.plain_pos
        js['ctx'] = base64.b64encode(self.ctx) if self.ctx is not None else None
        return js


class CensysTlsSec(object):
    """
    Downloading & processing of the Censys data - big x509 dataset
    """

    def __init__(self):
        self.args = None
        self.chain_cert_db = {}
        self.trace_logger = Tracelogger()
        self.fmagic = Fprinter()

        self.link_idx_offset = 0
        self.input_objects = []

        # Current state
        self.not_tls = 0
        self.not_cert_ok = 0
        self.not_chain_ok = 0
        self.not_parsed = 0
        self.not_rsa = 0
        self.num_found = 0

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
        self.last_record_seen = None
        self.last_record_flushed = None
        self.decompressor_checkpoints = {}
        self.state_loaded_ips = set()

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
        Process all input objects.
        :return: 
        """
        for iobj in self.input_objects:
            try:
                self.process_iobj(iobj)
            except Exception as e:
                logger.error('Exception when processing IOBJ: %s, %s' % (iobj, e))
                logger.info('Progress: %s' % self.ctr)
                self.trace_logger.log(e)

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
        if fsize > 1024*1024*1024*2:
            pos = fsize - 1024*1024*1024*1.5
            logger.info('Leafs file too big: %s, skipping to %s' % (fsize, pos))

            self.file_leafs_fh.seek(pos)
            x = self.file_leafs_fh.next()  # skip unfinished record
            pos += len(x)

        record_from_state_found = False
        terminate_with_record = False
        last_record = None
        last_id_seen = None
        for line in self.file_leafs_fh:
            ln = len(line)
            try:
                last_record = json.loads(line)
                last_id_seen = last_record['id']
                self.state_loaded_ips.add(last_record['ip'])
                self.ctr = max(self.ctr, last_record['id'])
                pos += ln

                if self.last_record_flushed is not None and self.last_record_flushed['ip'] == last_record['ip']:
                    logger.info('Found last record flushed in data file, ip: %s' % last_record['ip'])
                    record_from_state_found = True
                    break

            except Exception as e:
                terminate_with_record = True
                break

        logger.info('Operation resumed at leaf ctr: %s, last ip: %s'
                    % (self.ctr, utils.defvalkey(last_record, 'ip')))

        if self.last_record_flushed is not None and not record_from_state_found:
            logger.warning('Could not find the record from the state in the data file. Some data may be missing.')
            logger.info('Last record from state id: %s, last record data file id: %s'
                        % (self.last_record_resumed['id'], last_id_seen))
            raise ValueError('Incomplete data file')

        if terminate_with_record:
            logger.info('Leaf: Invalid record detected, position: %s' % pos)

            if not self.is_dry():
                self.file_leafs_fh.seek(pos)
                self.file_leafs_fh.truncate()
                self.file_leafs_fh.flush()

        return last_record

    def try_store_checkpoint(self, iobj, idx=None, resume_idx=None, resume_token=None):
        """
        Try-catch store checkpoint to handle situations when files cannot be flushed.
        In that case checkpoint cannot be stored, otherwise we won't be able to restore it properly.
        :param iobj: 
        :param idx: 
        :param resume_idx: 
        :param resume_token: 
        :return: 
        """
        attempts = 0
        while True:
            try:
                return self.store_checkpoint(iobj, idx, resume_idx, resume_token)

            except Exception as e:
                logger.error('Exception in storing a checkpoint %d: %s' % (attempts, e))
                logger.debug(traceback.format_exc())
                attempts += 1
                time.sleep(15)

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

        # Most importantly, flush data file buffers now so the state is in sync with the checkpoint.
        self.file_leafs_fh.flush()
        self.file_roots_fh.flush()

        js = collections.OrderedDict()
        js['iobj_name'] = input_name
        js['time'] = time.time()
        js['read_raw'] = self.read_data
        js['block_idx'] = idx
        js['ctr'] = self.ctr
        js['chain_ctr'] = self.chain_ctr
        js['resume_idx'] = resume_idx
        js['resume_token'] = resume_token
        js['num_found'] = self.num_found

        # Serialize input object state
        js['iobj'] = iobj.to_state()
        js['loaded_checkpoint'] = self.loaded_checkpoint

        # New decompressor checkpoint for random access read
        if self.cur_decompressor is not None and self.cur_decompressor.last_read_aligned:
            try:
                total_read_dec = self.cur_decompressor.data_read
                decctx = lz4framed.marshal_decompression_context(self.cur_decompressor.ctx)
                logger.debug('Decompressor state marshalled, size: %s B' % len(decctx))

                checkpoint = DecompressorCheckpoint(pos=total_read_dec, rec_pos=self.read_data,
                                                    plain_pos=self.processor.total_len, ctx=decctx)

                self.decompressor_checkpoints[total_read_dec] = checkpoint

                decctx_str = base64.b16encode(decctx)
                js['dec_ctx'] = decctx_str

            except Exception as e:
                logger.error('Exception when storing decompressor state: %s' % e)
                logger.warning(traceback.format_exc())

        js['dec_checks'] = [x.to_json() for x in self.decompressor_checkpoints.values()]

        # Last seen record
        js['last_record_seen'] = self.last_record_seen
        js['last_record_flushed'] = self.last_record_flushed

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
                self.decompressor_checkpoints = {
                    x['pos']: DecompressorCheckpoint(pos=x['pos'], rec_pos=x['rec_pos'],
                                                     plain_pos=x['plain_pos'], ctx=x['ctx'])
                    for x in js['dec_checks']
                }

            if 'last_record_seen' in js:
                self.last_record_resumed = js['last_record_seen']

            if 'last_record_flushed' in js:
                self.last_record_flushed = js['last_record_flushed']

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

        self.processor = newline_reader.NewlineReader(is_json=False)
        handle = iobj
        name = str(iobj)

        if name.endswith('lz4'):
            self.cur_decompressor = lz4framed.Decompressor(handle)
            handle = self.cur_decompressor

        if not self.is_dry() and (not self.args.continue1
                                  or not os.path.exists(file_leafs)
                                  or not os.path.exists(file_roots)):
            utils.safely_remove(file_leafs)
            utils.safely_remove(file_roots)
            self.file_leafs_fh = utils.safe_open(file_leafs, mode='w', chmod=0o644)
            self.file_roots_fh = utils.safe_open(file_roots, mode='w', chmod=0o644)

        elif self.args.continue1:
            logger.info('Continuing with the started files')
            self.file_leafs_fh = open(file_leafs, mode='r+' if not self.is_dry() else 'r')
            self.file_roots_fh = open(file_roots, mode='r+' if not self.is_dry() else 'r')
            self.restore_checkpoint(iobj)
            self.continue_leafs(file_leafs)

        with iobj:
            resume_token_found = False
            resume_token = None
            resume_idx = 0
            record_ctr = -1
            already_processed = 0
            read_start = self.read_data
            for idx, record in self.processor.process(handle):
                try:
                    record_ctr += 1
                    self.read_data += len(record)

                    # Check the checkpoint distance + boundary - process all newline chunks available
                    if self.read_data - self.last_report >= 1024*1024*1024 and self.processor.step_cur_last_element:
                        logger.info('...progress: %s GB, idx: %s, pos: %s GB, '
                                    'found: %s, mem: %04.8f MB, readpos: %s (%4.6f GB)'
                                    % (self.read_data/1024.0/1024.0/1024.0, idx, self.read_data,
                                       self.num_found,
                                       utils.get_mem_usage()/1024.0, iobj.tell(), iobj.tell()/1024.0/1024.0/1024.0))

                        self.last_report = self.read_data
                        self.try_store_checkpoint(iobj=iobj, idx=idx, resume_idx=resume_idx, resume_token=resume_token)

                        # Flush already seen IP database, not needed anymore
                        # we are too far from the resumed checkpoint
                        if read_start + 1024*1024*1024*2 > self.read_data:
                            self.state_loaded_ips = set()

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

    def fill_rsa_ne(self, ret, parsed):
        """
        Extracts mod, exponent from parsed
        :param ret: 
        :param parsed: 
        :return: 
        """
        try:
            mod16 = base64.b16encode(base64.b64decode(parsed['subject_key_info']['rsa_public_key']['modulus']))
            ret['n'] = '0x%s' % mod16
            ret['e'] = hex(int(parsed['subject_key_info']['rsa_public_key']['exponent']))
        except Exception as e:
            pass

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

    def fill_cert_info(self, ret, parsed, rec):
        """
        isCA and other.
        :param ret: 
        :param parsed: 
        :param rec: 
        :return: 
        """
        ret['ca'] = utils.defvalkeys(parsed, ['extensions', 'basic_constraints', 'is_ca'])
        issuer = utils.defvalkey(parsed, 'issuer')
        subject = utils.defvalkey(parsed, 'subject')
        ret['ss'] = issuer == subject
        ret['subject_dn'] = utils.defvalkey(parsed, 'subject_dn')
        ret['issuer_dn'] = utils.defvalkey(parsed, 'issuer_dn')
        ret['parents'] = utils.defvalkey(rec, 'parents')

        ret['crt_src'] = utils.defvalkey(rec, 'source')
        ret['seen_in_scan'] = utils.defvalkey(rec, 'seen_in_scan')
        ret['valid_nss'] = utils.defvalkey(rec, 'valid_nss')
        ret['was_valid_nss'] = utils.defvalkey(rec, 'was_valid_nss')
        ret['current_valid_nss'] = utils.defvalkey(rec, 'current_valid_nss')

    def process_record(self, idx, record):
        """
        Current record analysis

        :param idx: 
        :param record: 
        :return: 
        """
        record['id'] = self.ctr
        self.last_record_seen = record
        raw = utils.defvalkey(record, 'raw')
        parsed = utils.defvalkey(record, 'parsed')

        # Process server cert
        if parsed is None:
            self.not_parsed += 1  # TODO: parse raw cert if needed
            return

        try:
            ret = collections.OrderedDict()
            if 'rsa_public_key' not in parsed['subject_key_info']:
                self.not_rsa += 1
                return

            mod16 = base64.b16encode(base64.b64decode(parsed['subject_key_info']['rsa_public_key']['modulus']))
            if not self.fmagic.test16(mod16):
                return

            self.num_found += 1
            ret['id'] = self.ctr
            ret['fprint256'] = utils.defvalkey(parsed, 'fingerprint_sha256')
            self.fill_cn_src(ret, parsed)
            self.fill_rsa_ne(ret, parsed)
            self.fill_cert_info(ret, parsed, record)

            if raw is not None:
                rawb = base64.b64decode(raw)
                ret['fprint'] = hashlib.sha1(rawb).hexdigest()
            ret['raw'] = raw

            self.last_record_flushed = record
            if not self.is_dry():
                self.file_leafs_fh.write(json.dumps(ret) + '\n')

        except Exception as e:
            logger.warning('Certificate processing error %s : %s' % (self.ctr, e))
            self.trace_logger.log(e)
            self.not_cert_ok += 1

    def _build_link_object(self, url, rec):
        """
        Builds a link object to be processed
        :param url: 
        :param rec: 
        :return: 
        """
        return input_obj.ReconnectingLinkInputObject(url=url, rec=rec, timeout=5*60, max_reconnects=1000)

    def generate_workset(self):
        """
        Prepares input objects for processing
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

    def work(self):
        """
        Entry point after argument processing.
        :return: 
        """
        self.generate_workset()
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
   app = CensysTlsSec()
   app.main()


if __name__ == '__main__':
    main()


