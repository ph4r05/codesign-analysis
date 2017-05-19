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
import datetime
import random
import shutil
from trace_logger import Tracelogger


logger = logging.getLogger(__name__)
coloredlogs.install(level=logging.DEBUG)


def month_key_fnc(dt):
    """
    Month key function from timestamp
    :param tstamp: 
    :return: 
    """
    return dt.year, dt.month


def keyfnc(x):
    """
    Date_utc key function
    :param x: 
    :return: 
    """
    return month_key_fnc(datetime.datetime.utcfromtimestamp(x['date_utc']))


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
        self.fmagic = None

    def main(self):
        """
        Main entry point, argument processing
        :return:
        """
        utils.monkey_patch_asn1_time()

        parser = argparse.ArgumentParser(description='Processes Sonar/ECO SSL incremental cert files, '
                                                     'generates json for classification')

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

        parser.add_argument('--months', dest='months', default=False, action='store_const', const=True,
                            help='Merge incremental snapshots on-per month basis')

        parser.add_argument('--months-full', dest='months_full', default=False, action='store_const', const=True,
                            help='One per month full snapshot')

        parser.add_argument('--sec', dest='sec', default=False, action='store_const', const=True,
                            help='Sec')

        parser.add_argument('--download-only', dest='download_only', default=False, action='store_const', const=True,
                            help='Performs only download of all links needed for analysis later')

        self.args = parser.parse_args()

        if self.args.sec:
            import sec
            self.fmagic = sec.Fprinter()

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

        jsdb.sort(key=lambda x: x['date_utc'])
        if self.args.months or self.args.months_full:
            self.work_eco_months(jsdb)
            return

        for test_idx, js_rec in enumerate(jsdb):
            if int(test_idx % self.args.proc_total) != int(self.args.proc_cur):
                continue

            datepart = js_rec['date']
            hostfile = js_rec['hostfile']
            certfile = js_rec['certfile']
            logger.info('Processing eco dataset %s, %s rec: %s' % (test_idx, datepart, json.dumps(js_rec)))
            self.process_dataset(test_idx, datepart, certfile, hostfile)

    def work_eco_months(self, jsdb):
        """
        Months based processing
        :param jsdb: 
        :return: 
        """
        data = sorted(jsdb, key=lambda x: x['date_utc'])  # stronger sorting function than keyfnc. breaks in-month ties.
        test_idx = -1
        for k, g in itertools.groupby(data, keyfnc):
            test_idx += 1
            group_recs = list(g)

            if int(test_idx % self.args.proc_total) != int(self.args.proc_cur):
                continue

            if self.args.months_full:
                test_name = '%s_%02d_fullmerge' % (k[0], k[1])
            else:
                test_name = '%s_%s_merge' % (k[0], k[1])

            hostfiles = [js_rec['hostfile'] for js_rec in group_recs]
            if len(hostfiles) == 0:
                logger.warning('Empty host files for %s %s' % (k, json.dumps(group_recs)))
                continue
            hostfile = hostfiles[-1]  # take the last host file to make it simple

            # month full - full snapshot, all certificates till now.
            if self.args.months_full:
                certfiles = [js_rec['certfile'] for js_rec in data if js_rec['date_utc'] <= group_recs[-1]['date_utc']]
            else:
                certfiles = [js_rec['certfile'] for js_rec in group_recs]

            certfile = input_obj.MergedInputObject([
                input_obj.FileLikeInputObject(open_call=lambda x: gzip.open(x.desc), desc=ff) for ff in certfiles
            ])

            logger.info('Processing eco dataset - merged %s, %s rec: %s'
                        % (test_idx, test_name, json.dumps(group_recs)))
            logger.info('certfiles: %s' % json.dumps(certfiles))
            logger.info('hostfiles: %s' % json.dumps(hostfiles))
            self.process_dataset(test_idx, test_name, certfile, hostfile)

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

        jsdb_ids = {x['id']: x for x in jsdb['data'] if x['id'] in testrng}

        if self.args.months or self.args.months_full or self.args.download_only:
            self.work_sonar_months(jsdb_ids)
            return

        for test_idx in testrng:
            if int(test_idx % args.proc_total) != int(args.proc_cur):
                continue

            rec = jsdb_ids[test_idx]
            certfile, hostfile, datepart = self._sonar_get_certfile_hostfile(rec)
            self.process_dataset(test_idx, datepart, certfile, hostfile)

    def work_sonar_months(self, jsdb_ids):
        """
        Month based processing
        :param jsdb_ids: 
        :return: 
        """
        jsdb = sorted(jsdb_ids.values(), key=lambda x: x['date_utc'])
        test_idx = -1
        for k, g in itertools.groupby(jsdb, keyfnc):
            test_idx += 1
            group_recs = list(g)

            if int(test_idx % self.args.proc_total) != int(self.args.proc_cur):
                continue

            if self.args.months_full:
                test_name = '%s_%02d_fullmerge' % (k[0], k[1])
            else:
                test_name = '%s_%s_merge' % (k[0], k[1])

            # load host files, prepare the last one
            hostfiles = utils.drop_nones([self._sonar_get_hostrec(x) for x in group_recs])
            hostfiles = [self._sonar_augment_filepaths(x) for x in hostfiles]
            if len(hostfiles) == 0:
                logger.warning('Empty host files for %s %s' % (k, json.dumps(group_recs)))
                continue

            hostfile = self._iobj_fetchable(path=hostfiles[-1]['fpath'], url=hostfiles[-1]['href'])

            # cert file loading - month / month full
            if self.args.months_full:
                certfiles = [self._sonar_get_certrec(x) for x in jsdb if x['date_utc'] <= group_recs[-1]['date_utc']]
                hostfiles2 = [self._sonar_get_hostrec(x) for x in jsdb if x['date_utc'] <= group_recs[-1]['date_utc']]
            else:
                certfiles = [self._sonar_get_certrec(x) for x in group_recs]
                hostfiles2 = hostfiles

            certfiles = utils.drop_nones(certfiles)
            self._sonar_extend_certfiles(hostfiles=hostfiles2, certfiles=certfiles)

            certfiles = [self._sonar_augment_filepaths(x) for x in certfiles]

            if self.args.download_only:
                self._sonar_download(certfiles, hostfiles)
                continue

            certfile = input_obj.MergedInputObject(list(reversed([
                self._iobj_fetchable(path=x['fpath'], url=x['href']) for x in certfiles
                if '20131030-20150518' not in x['name']
            ])))

            logger.info('Processing sonar dataset - merged %s, %s rec: %s'
                        % (test_idx, test_name, json.dumps(group_recs)))
            logger.info('certfiles: %s' % json.dumps(certfiles))
            logger.info('hostfiles: %s' % json.dumps(hostfiles))
            self.process_dataset(test_idx, test_name, certfile, hostfile)

    def _sonar_download(self, certfiles, hostfiles):
        """
        Download all missing certfiles and the latest hostfile
        :param certfiles: 
        :param hostfiles: 
        :return: 
        """
        to_download = []
        files_to_check = certfiles + [hostfiles[-1]]

        for cur in files_to_check:
            if '20131030-20150518' in cur['name']:
                continue
            if cur is not None and not os.path.exists(cur['fpath']):
                to_download.append((cur['href'], cur['fpath']))

        for down_rec in to_download:
            logger.debug('Downloading: %s %s' % down_rec)
            tmpfile = '%s.%s.%s' % (down_rec[1], int(time.time() * 1000), random.randint(0, 10000))
            try:
                utils.download_file(down_rec[0], tmpfile, 3)
                shutil.move(tmpfile, down_rec[1])

            except Exception as e:
                logger.error('Exception when downloading %s : %s' % (down_rec, e))
                self.trace_logger.log(e)

            finally:
                utils.safely_remove(tmpfile)

    def _sonar_get_filerec(self, rec, name):
        """
        Sonar record 
        :param rec: 
        :param name: 
        :return: 
        """
        files = rec['files']
        filerec = None
        for tmprec in files:
            if name in tmprec:
                filerec = files[tmprec]
                break
        return filerec

    def _sonar_get_certrec(self, rec):
        """
        Return cert file record
        :param rec: 
        :return: 
        """
        return self._sonar_get_filerec(rec, '_certs.gz')

    def _sonar_get_hostrec(self, rec):
        """
        Return cert file record
        :param rec: 
        :return: 
        """
        return self._sonar_get_filerec(rec, '_hosts.gz')

    def _sonar_get_filepath(self, filerec):
        """
        Returns file path on the storage for the file record
        :param filerec: 
        :return: 
        """
        fname = filerec['name']
        fname_2 = os.path.basename(fname)
        return os.path.join(self.args.datadir, fname_2)

    def _sonar_augment_filepaths(self, filerec):
        """
        Augments a record with file path
        :param lst: 
        :return: 
        """
        if filerec is None:
            return None
        filerec['fpath'] = self._sonar_get_filepath(filerec)
        return filerec

    def _sonar_extend_certfiles(self, hostfiles, certfiles):
        """
        Extends certfiles with new certificates derived from hostfiles based on file existence check.
        Links for old samples does not contain cert files but we generated them by recoding.
        :param hostfiles: 
        :param certfiles: 
        :return: 
        """
        existing_names = set([os.path.basename(x['name']) for x in certfiles])
        for rec in hostfiles:
            name = rec['name']
            bname = os.path.basename(name)
            parts = bname.split('_', 1)
            certfile_bname = '%s_certs.gz' % parts[0]
            if certfile_bname in existing_names:
                continue

            certfile = os.path.join(self.args.datadir, certfile_bname)
            if os.path.exists(certfile):
                js = collections.OrderedDict()
                js['name'] = certfile_bname
                js['href'] = None
                js['size'] = None
                js['hash'] = None
                certfiles.append(js)
        return certfiles

    def _sonar_get_certfile_hostfile(self, rec):
        """
        Returns certfile, hostfile, datepart tuple for the sonar record
        :param rec: 
        :return: 
        """
        filerec = self._sonar_get_hostrec(rec)
        fname = filerec['name']

        # 20131104/20131104_hosts.gz
        fname_2 = os.path.basename(fname)
        dateparts = fname_2.split('_')
        datepart = dateparts[0]

        certfile = os.path.join(self.args.datadir, '%s_certs.gz' % datepart)
        hostfile = os.path.join(self.args.datadir, '%s_hosts.gz' % datepart)
        return certfile, hostfile, datepart

    def load_host_sonar(self, hostfile):
        """
        Loads host file to the fprints db
        :param hostfile: 
        :return: 
        """
        fprints_db = collections.defaultdict(list)

        with self._open_file(hostfile) as cf:
            for line in cf:
                linerec = line.strip().split(',')
                ip = linerec[0]
                fprints = linerec[1:]
                for fprint in fprints:
                    fprint_s = utils.strip_hex_prefix(fprint.strip()).lower()
                    lst = fprints_db[fprint_s]
                    lst.append(ip)
        return fprints_db

    def load_host_eco(self, hostfile):
        """
        Loads host file to fprints db - eco format
        :param hostfile: 
        :return: 
        """
        fprints_db = collections.defaultdict(list)

        # Input file may be input object - do nothing. Or simple case - a gzip file
        with self._open_file(hostfile) as cf:
            for line in cf:
                linerec = line.strip().split(',')
                ip = linerec[0].strip()
                fprint = utils.strip_hex_prefix(linerec[2].strip()).lower()

                lst = fprints_db[fprint]
                lst.append(ip)
        return fprints_db

    def _exists(self, x):
        """
        returns true if input is valid & readable
        :param x: 
        :return: 
        """
        if isinstance(x, input_obj.InputObject):
            return True
        return os.path.exists(x)

    def _open_file(self, x):
        """
        Returns readable file handle with context manager support
        :param x: 
        :return: 
        """
        if isinstance(x, input_obj.InputObject):
            return x

        if x.endswith('.gz') or x.endswith('.gzip'):
            return gzip.open(x)

        return open(x)

    def process_dataset(self, test_idx, datepart, certfile, hostfile):
        """
        Processes single dataset, generates jsons
        :param test_idx: test index
        :param datepart: test name prefix, usually the date of the snapshot
        :param certfile: file with the certificates to process.
        :param hostfile: host IP -> fprint array mapping file name, snapshot in time.
        :return: 
        """
        logger.info('Test idx: %d date part: %s, ram: %s MB' % (test_idx, datepart, utils.get_mem_mb()))
        jsonfile = os.path.join(self.args.datadir, '%s_certs.json' % datepart)
        jsonufile = os.path.join(self.args.datadir, '%s_certs.uniq.json' % datepart)
        jsoncafile = os.path.join(self.args.datadir, '%s_ca_certs.json' % datepart)
        finishfile = os.path.join(self.args.datadir, '%s_process.finished' % datepart)

        if not self._exists(certfile):
            logger.error('Cert file does not exist %s' % certfile)
            return

        if not self._exists(hostfile):
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

        jsoncafile_fh = open(jsoncafile, 'w')

        nrsa = self.args.nrsa
        months_full = self.args.months_full

        # Input file may be input object - do nothing. Or simple case - a gzip file
        with self._open_file(certfile) as cf:
            for line in cf:
                try:
                    line_ctr += 1
                    js = collections.OrderedDict()
                    linerec = line.strip().split(',')
                    fprint = utils.strip_hex_prefix(linerec[0].strip()).lower()
                    cert_b64 = linerec[1]
                    fprint_in_db = fprint in fprints_db

                    if months_full and not fprint_in_db:
                        continue

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
                            pubnum = pub.public_numbers()
                            js['e'] = '0x%x' % pubnum.e
                            js['n'] = '0x%x' % pubnum.n
                            js['nnum'] = pubnum.n
                            if self.fmagic is not None:
                                js['sec'] = self.fmagic.test16('%x' % pubnum.n)
                        else:
                            js['nnum'] = 9e99

                        js['info'] = {'ip': []}
                        if fprint in fprints_db:
                            js['info']['ip'] = list(set(fprints_db[fprint]))

                        if js['ca']:
                            js['raw'] = cert_b64

                        if crt_is_rsa:
                            js_db.append(js)

                        if crt_is_ca:
                            jsoncafile_fh.write('%s\n' % json.dumps(js))

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
        jsoncafile_fh.close()

        # Sort
        js_db.sort(key=lambda x: x['nnum'])
        logger.info('Sorted, mem: %s MB' % utils.get_mem_mb())

        with open(jsonfile, 'w') as fh:
            for rec in js_db:
                del rec['nnum']
                fh.write(json.dumps(rec) + '\n')

        logger.info('JSON file produced, mem: %s MB' % utils.get_mem_mb())

        # Duplicate removal
        js_db.sort(key=lambda x: x['fprint'])
        with open(jsonufile, 'w') as fh:
            for k, g in itertools.groupby(js_db, key=lambda x: x['fprint']):
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

    def _iobj_fetchable(self, path, url):
        """
        Returns new input object, either local or downloads to a local file
        :param path: 
        :param url: 
        :return: 
        """
        if os.path.exists(path):
            iobj = input_obj.FileInputObject(fname=path)
        elif url is not None:
            iobj = input_obj.ReconnectingLinkInputObject(url=url, rec=path)
            iobj = input_obj.TeeInputObject(parent_fh=iobj, copy_fname=path, close_copy_on_exit=True)
        else:
            return None

        gz = path is not None and (path.endswith('.gz') or path.endswith('.gzip'))
        gz |= url is not None and (url.endswith('.gz') or url.endswith('.gzip'))
        if gz:
            iobj = input_obj.GzipInputObject(iobj)
        iobj.rec = path

        return iobj


if __name__ == '__main__':
    SonarSSLProcess().main()




