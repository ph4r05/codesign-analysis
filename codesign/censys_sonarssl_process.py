#!/usr/bin/env python
# -*- coding: utf-8 -*-
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

__author__ = 'dusanklinec'

from past.builtins import cmp
import argparse
import json
import os
import sys
import collections
import itertools
import traceback
import logging
import math
import collections
import base64
import utils
import coloredlogs
import time
import input_obj
import gzip
import gzipinputstream
from datetime import datetime
from trace_logger import Tracelogger


logger = logging.getLogger(__name__)
coloredlogs.install(level=logging.DEBUG)


class SonarSSLProcess(object):
    """
    Processing censys datasets
    Stored sorted fingerprints, scanning big database of fprints, producing new (incremental) certificates.
    Produces JSON for classification
    
    https://scans.io/study/sonar.ssl
    """

    def __init__(self):
        self.args = None
        self.is_eco = False
        self.trace_logger = Tracelogger(logger=logger)

    def main(self):
        """
        Main entry point, argument processing
        :return:
        """
        utils.monkey_patch_asn1_time()

        parser = argparse.ArgumentParser(description='Processes sonar ssl incremental cert files, generates json for classification')

        parser.add_argument('--url', dest='url', nargs=argparse.ZERO_OR_MORE, default=[],
                            help='censys links')

        parser.add_argument('--json', dest='json', default=None,
                            help='sonar links json')

        parser.add_argument('--eco-json', dest='eco_json', default=None,
                            help='https ecosystem json result file')

        parser.add_argument('--datadir', dest='datadir', default='.',
                            help='datadir')

        parser.add_argument('--proc-total', dest='proc_total', default=1, type=int,
                            help='Total number of processes to run')

        parser.add_argument('--proc-cur', dest='proc_cur', default=0, type=int,
                            help='ID of the current process')

        parser.add_argument('--nrsa', dest='nrsa', default=False, action='store_const', const=True,
                            help='Store also non-rsa intermediates')

        self.args = parser.parse_args()
        self.work()

    def work(self):
        """
        Work entry point, arguments processed, do the job
        :return: 
        """
        args = self.args
        self.is_eco = args.eco_json is not None

        if self.is_eco:
            logger.info('Processing ECO dataset')
            self.work_eco()
        else:
            logger.info('Processing Sonar dataset')
            self.work_sonar()

    def work_eco(self):
        """
        Processes HTTPS ecosystem dataset
        :return: 
        """
        jsdb = []
        with open(self.args.eco_json, 'r') as fh:
            for rec in fh:
                js_rec = json.loads(rec)
                jsdb.append(js_rec)

        for test_idx, js_rec in enumerate(jsdb):
            if int(test_idx % self.args.proc_total) != int(self.args.proc_cur):
                continue

            datepart = js_rec['date']
            hostfile = js_rec['hostfile']
            certfile = js_rec['certfile']
            logger.info('Processing eco dataset %s, %s rec: %s' % (test_idx, datepart, json.dumps(js_rec)))
            self.process_dataset(test_idx, datepart, certfile, hostfile)

    def work_sonar(self):
        """
        Processes sonar dataset - jobs generated from the link json, different format
        :return: 
        """
        args = self.args
        testrng = range(10, 93)

        jsdb = None
        with open(args.json, 'r') as fh:
            jsdb = json.load(fh)

        jsdb_ids = {x['id']: x for x in jsdb['data']}
        for test_idx in testrng:
            if int(test_idx % args.proc_total) != int(args.proc_cur):
                continue

            files = jsdb_ids[test_idx]['files']
            filerec = None
            for tmprec in files:
                if '_hosts.gz' in tmprec:
                    filerec = files[tmprec]
                    break

            fname = filerec['name']

            # 20131104/20131104_hosts.gz
            fname_2 = os.path.basename(fname)
            dateparts = fname_2.split('_')
            datepart = dateparts[0]

            certfile = os.path.join(args.datadir, '%s_certs.gz' % datepart)
            hostfile = os.path.join(args.datadir, '%s_hosts.gz' % datepart)
            self.process_dataset(test_idx, datepart, certfile, hostfile)

    def load_host_sonar(self, hostfile):
        """
        Loads host file to the fprints db
        :param hostfile: 
        :return: 
        """
        fprints_db = collections.defaultdict(list)
        with gzip.open(hostfile) as cf:
            for line in cf:
                linerec = line.strip().split(',')
                ip = linerec[0]
                fprints = linerec[1:]
                for fprint in fprints:
                    lst = fprints_db[fprint]
                    lst.append(ip)
        return fprints_db

    def load_host_eco(self, hostfile):
        """
        Loads host file to fprints db - eco format
        :param hostfile: 
        :return: 
        """
        fprints_db = collections.defaultdict(list)
        with gzip.open(hostfile) as cf:
            for line in cf:
                linerec = line.strip().split(',')
                ip = linerec[0].strip()
                fprint = utils.strip_hex_prefix(linerec[2].strip())

                lst = fprints_db[fprint]
                lst.append(ip)
        return fprints_db

    def process_dataset(self, test_idx, datepart, certfile, hostfile):
        """
        Processes single dataset, generates jsons
        :param test_idx: 
        :param datepart: 
        :param certfile: 
        :param hostfile: 
        :return: 
        """
        logger.info('Test idx: %d date part: %s, ram: %s MB' % (test_idx, datepart, utils.get_mem_mb()))
        jsonfile = os.path.join(self.args.datadir, '%s_certs.json' % datepart)
        jsonufile = os.path.join(self.args.datadir, '%s_certs.uniq.json' % datepart)
        finishfile = os.path.join(self.args.datadir, '%s_process.finished' % datepart)

        if not os.path.exists(certfile):
            logger.error('Cert file does not exist %s' % certfile)
            return

        if not os.path.exists(hostfile):
            logger.error('Host file does not exist %s' % hostfile)
            return

        if os.path.exists(finishfile):
            logger.info('Test finished')
            return

        # Load host file, ip->fprint associations.
        logger.info('Building fprint database ram: %s MB' % utils.get_mem_mb())
        fprints_db = {}
        if self.is_eco:
            fprints_db = self.load_host_eco(hostfile)
        else:
            fprints_db = self.load_host_sonar(hostfile)

        logger.info('Processed host file, db size: %s, ram: %s MB' % (len(fprints_db), utils.get_mem_mb()))

        # Process certfile - all certificates from the file will be added to the result
        last_info_time = 0
        last_info_line = 0
        line_ctr = 0
        js_db = []
        nrsa = self.args.nrsa
        with gzip.open(certfile) as cf:
            for line in cf:
                try:
                    line_ctr += 1
                    js = collections.OrderedDict()
                    linerec = line.strip().split(',')
                    fprint = linerec[0]
                    cert_b64 = linerec[1]
                    cert_bin = base64.b64decode(cert_b64)

                    cert = utils.load_x509_der(cert_bin)
                    pub = cert.public_key()

                    # Add to the dataset - either RSA key OR (isCA && take non-RSA keys)
                    crt_is_ca = None
                    crt_is_rsa = isinstance(pub, RSAPublicKey)
                    if nrsa:
                        crt_is_ca = utils.try_is_ca(cert)
                    crt_add_to_js = crt_is_rsa or (nrsa and crt_is_ca)

                    if crt_add_to_js:
                        not_before = cert.not_valid_before
                        cname = utils.try_get_cname(cert)

                        js['source'] = [cname, not_before.strftime('%Y-%m-%d')]
                        js['ca'] = crt_is_ca if crt_is_ca is not None else utils.try_is_ca(cert)
                        js['ss'] = utils.try_is_self_signed(cert)
                        js['fprint'] = fprint
                        if crt_is_rsa:
                            js['e'] = '0x%x' % pub.public_numbers().e
                            js['n'] = '0x%x' % pub.public_numbers().n
                            js['nnum'] = pub.public_numbers().n
                        else:
                            js['nnum'] = 9e99

                        js['info'] = {'ip': []}
                        if fprint in fprints_db:
                            js['info']['ip'] = fprints_db[fprint]

                        if js['ca']:
                            js['raw'] = cert_b64
                        js_db.append(js)

                        if line_ctr - last_info_line >= 1000 and time.time() - last_info_time >= 30:
                            logger.info('Progress, line: %9d, mem: %s MB, db size: %9d, from last: %5d, cname: %s'
                                        % (line_ctr, utils.get_mem_mb(), len(js_db), line_ctr - last_info_line, cname))
                            last_info_time = time.time()
                            last_info_line = line_ctr

                except ValueError as e:
                    logger.error('Exception in rec processing (ValueError): %s, line %9d' % (e, line_ctr))
                    self.trace_logger.log(e)

                except Exception as e:
                    logger.error('Exception in rec processing: %s' % e)
                    self.trace_logger.log(e)

        logger.info('Processed certificate file, size: %d, mem: %s MB' % (len(js_db), utils.get_mem_mb()))

        # Sort
        js_db.sort(key=lambda x: x['nnum'])
        logger.info('Sorted, mem: %s MB' % utils.get_mem_mb())

        with open(jsonfile, 'w') as fh:
            for rec in js_db:
                del rec['nnum']
                fh.write(json.dumps(rec) + '\n')

        logger.info('JSON file produced, mem: %s MB' % utils.get_mem_mb())

        # Duplicate removal
        with open(jsonufile, 'w') as fh:
            for k, g in itertools.groupby(js_db, key=lambda x: x['n']):
                grp = [x for x in g]
                g0 = grp[0]
                js = collections.OrderedDict(g0)
                js['count'] = len(grp)
                ips = []
                for rec in grp:
                    ips += rec['info']['ip']
                js['info']['ip'] = ips
                fh.write(json.dumps(js) + '\n')

        utils.try_touch(finishfile)


if __name__ == '__main__':
    SonarSSLProcess().main()




