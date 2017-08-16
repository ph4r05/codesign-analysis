#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Key fingerprinting

The fingerprinter supports the following formats:

    - X509 Certificate, DER encoded, one per file, *.der, *.crt
    - X509 Certificate, PEM encoded, more per file, *.pem
    - RSA PEM encoded private key, public key, more per file, *.pem (has to have correct header -----BEGIN RSA...)
    - SSH public key, *.pub, starting with "ssh-rsa", one per line
    - ASC encoded PGP key, *.pgp, *.asc. More per file, has to have correct header -----BEGIN PGP...
    - APK android application, *.apk
    - one modulus per line text file *.txt, modulus can be
        a) base64 encoded number, b) hex coded number, c) decimal coded number
    - JSON file with moduli, one record per line, record with modulus has
        key "mod" (int, base64, hex, dec encoding supported)

Script requirements:

    - Tested on Python 2.7.13
    - pip install cryptography pgpdump coloredlogs future six pycrypto>=2.6
    - some system packages are usually needed for pip to install dependencies (like gcc):
        yum install gcc openssl-devel libffi-devel dialog

"""

import json
import argparse
import logging
import coloredlogs
import types
import base64
import hashlib
import sys
import os
import re
import binascii
import collections
import traceback


#            '%(asctime)s %(hostname)s %(name)s[%(process)d] %(levelname)s %(message)s'
LOG_FORMAT = '%(asctime)s [%(process)d] %(levelname)s %(message)s'


logger = logging.getLogger(__name__)
coloredlogs.install(level=logging.INFO, fmt=LOG_FORMAT)


#
# Helper functions & classes
#

def strip_hex_prefix(x):
    """
    Strips possible hex prefixes from the strings
    :param x:
    :return:
    """
    if x.startswith('0x'):
        return x[2:]
    if x.startswith('\\x'):
        return x[2:]
    return x


def error_message(e, message=None, cause=None):
    """
    Formats exception message + cause
    :param e:
    :param message:
    :param cause:
    :return: formatted message, includes cause if any is set
    """
    if message is None and cause is None:
        return None
    elif message is None:
        return '%s, caused by %r' % (e.__class__, cause)
    elif cause is None:
        return message
    else:
        return '%s, caused by %r' % (message, cause)


def format_pgp_key(key):
    """
    Formats PGP key in 16hex digits
    :param key:
    :return:
    """
    if key is None:
        return None
    if isinstance(key, (types.IntType, types.LongType)):
        return '%016x' % key
    elif isinstance(key, types.ListType):
        return [format_pgp_key(x) for x in key]
    else:
        key = key.strip()
        key = strip_hex_prefix(key)
        return format_pgp_key(int(key, 16))


class Tracelogger(object):
    """
    Prints traceback to the debugging logger if not shown before
    """

    def __init__(self, logger=None):
        self.logger = logger
        self._db = set()

    def log(self, cause=None, do_message=True, custom_msg=None):
        """
        Loads exception data from the current exception frame - should be called inside the except block
        :return:
        """
        message = error_message(self, cause=cause)
        exc_type, exc_value, exc_traceback = sys.exc_info()
        traceback_formatted = traceback.format_exc()
        traceback_val = traceback.extract_tb(exc_traceback)

        md5 = hashlib.md5(traceback_formatted).hexdigest()

        if md5 in self._db:
            # self.logger.debug('Exception trace logged: %s' % md5)
            return

        if custom_msg is not None and cause is not None:
            self.logger.debug('%s : %s' % (custom_msg, cause))
        elif custom_msg is not None:
            self.logger.debug(custom_msg)
        elif cause is not None:
            self.logger.debug('%s' % cause)

        self.logger.debug(traceback_formatted)
        self._db.add(md5)


#
# Main fingerprinting tool
#

class IontFingerprinter(object):
    """
    Key fingerprinter
    """

    def __init__(self):
        self.args = None
        self.trace_logger = Tracelogger(logger)

        self.tested = 0
        self.num_rsa = 0
        self.num_pem_certs = 0
        self.num_der_certs = 0
        self.num_rsa_keys = 0
        self.num_pgp_masters = 0
        self.num_pgp_total = 0
        self.num_ssh = 0
        self.num_json = 0
        self.num_apk = 0
        self.num_ldiff_cert = 0
        self.found = 0

    def has_fingerprint_test(self, modulus):
        """
        Not sure :)
        :param modulus:
        :return:
        """
        return False

    has_fingerprint = has_fingerprint_test

    def file_matches_extensions(self, fname, extensions):
        """
        True if file matches one of extensions
        :param fname:
        :param extensions:
        :return:
        """
        if not isinstance(extensions, types.ListType):
            extensions = [extensions]
        for ext in extensions:
            if fname.endswith('.%s' % ext):
                return True
        return False

    def process_inputs(self):
        """
        Processes input data
        :return:
        """
        files = self.args.files
        for fname in files:
            if fname == '-':
                fh = sys.stdin

            elif fname.endswith('.tar') or fname.endswith('.tar.gz'):
                self.process_tar(fname)
                continue

            elif not os.path.isfile(fname):
                self.process_dir(fname)
                continue

            else:
                fh = open(fname, 'rb')

            with fh:
                data = fh.read()
                self.process_file(data, fname)
        pass

    def process_tar(self, fname):
        """
        Tar(gz) archive processing
        :param fname:
        :return:
        """
        import tarfile  # lazy import, only when needed
        with tarfile.open(fname) as tr:
            members = tr.getmembers()
            for member in members:
                if not member.isfile():
                    continue
                fh = tr.extractfile(member)
                self.process_file(fh.read(), member.name)

    def process_dir(self, dirname):
        """
        Directory processing
        :param dirname:
        :return:
        """
        sub_rec = [f for f in os.listdir(dirname)]
        for fname in sub_rec:
            full_path = os.path.join(dirname, fname)

            if os.path.isfile(full_path):
                with open(full_path, 'rb') as fh:
                    self.process_file(fh.read(), fname)
            else:
                self.process_dir(full_path)

    def process_file(self, data, name):
        """
        Processes a single file
        :param data:
        :param name:
        :return:
        """
        try:
            self.process_file_autodetect(data, name)
            return

        except Exception as e:
            logger.debug('Excetion processing file %s : %s' % (name, e))
            self.trace_logger.log(e)

        # autodetection fallback - all formats
        logger.debug('processing %s as PEM' % name)
        self.process_pem(data, name)

        logger.debug('processing %s as DER' % name)
        self.process_der(data, name)

        logger.debug('processing %s as PGP' % name)
        self.process_pgp(data, name)

        logger.debug('processing %s as SSH' % name)
        self.process_ssh(data, name)

        logger.debug('processing %s as JSON' % name)
        self.process_json(data, name)

        logger.debug('processing %s as APK' % name)
        self.process_apk(data, name)

        logger.debug('processing %s as MOD' % name)
        self.process_mod(data, name)

        logger.debug('processing %s as LDIFF' % name)
        self.process_ldiff(data, name)

    def process_file_autodetect(self, data, name):
        """
        Processes a single file - format autodetection
        :param data:
        :param name:
        :return:
        """
        is_ssh_file = data.startswith('ssh-rsa') or 'ssh-rsa ' in data
        is_pgp_file = data.startswith('-----BEGIN PGP')
        is_pem_file = data.startswith('-----BEGIN') and not is_pgp_file
        is_ldiff_file = 'binary::' in data

        is_pgp = is_pgp_file or (self.file_matches_extensions(name, ['pgp', 'gpg', 'key', 'pub', 'asc'])
                  and not is_ssh_file
                  and not is_pem_file)
        is_pgp |= self.args.file_pgp

        is_crt_ext = self.file_matches_extensions(name, ['der', 'crt', 'cer', 'cert', 'x509', 'key', 'pub', 'ca'])

        is_pem = self.file_matches_extensions(name, 'pem') or is_pem_file
        is_pem |= self.args.file_pem

        is_der = not is_pem and not is_ssh_file and not is_pgp_file and is_crt_ext
        is_der |= self.args.file_der

        is_ssh = self.file_matches_extensions(name, ['ssh', 'pub']) or is_ssh_file
        is_ssh |= self.args.file_ssh

        is_apk = self.file_matches_extensions(name, 'apk')

        is_mod = self.file_matches_extensions(name, ['txt', 'mod', 'mods', 'moduli'])
        is_mod |= not is_pem and not is_der and not is_pgp and not is_ssh_file and not is_apk
        is_mod |= self.args.file_mod

        is_json = self.file_matches_extensions(name, ['json', 'js']) or data.startswith('{') or data.startswith('[')
        is_json |= self.args.file_json

        is_ldiff = self.file_matches_extensions(name, ['ldiff', 'ldap']) or is_ldiff_file
        is_ldiff |= self.args.file_ldiff

        det = is_pem or is_der or is_pgp or is_ssh or is_mod or is_json or is_apk
        if is_pem:
            logger.debug('processing %s as PEM' % name)
            self.process_pem(data, name)

        if is_der:
            logger.debug('processing %s as DER' % name)
            self.process_der(data, name)

        if is_pgp:
            logger.debug('processing %s as PGP' % name)
            self.process_pgp(data, name)

        if is_ssh:
            logger.debug('processing %s as SSH' % name)
            self.process_ssh(data, name)

        if is_json:
            logger.debug('processing %s as JSON' % name)
            self.process_json(data, name)

        if is_apk:
            logger.debug('processing %s as APK' % name)
            self.process_apk(data, name)

        if is_mod:
            logger.debug('processing %s as MOD' % name)
            self.process_mod(data, name)

        if is_ldiff:
            logger.debug('processing %s as LDIFF' % name)
            self.process_ldiff(data, name)

        if not det:
            logger.debug('Undetected (skipped) file: %s' % name)

    def process_pem(self, data, name):
        """
        PEM processing - splitting further by the type of the records
        :param data:
        :param name:
        :return:
        """
        try:
            parts = re.split(r'-{5,}BEGIN', data)
            if len(parts) == 0:
                return

            if len(parts[0]) == 0:
                parts.pop(0)

            crt_arr = ['-----BEGIN' + x for x in parts]
            for idx, pem_rec in enumerate(crt_arr):
                pem_rec = pem_rec.strip()
                if len(pem_rec) == 0:
                    continue

                if pem_rec.startswith('-----BEGIN CERTIF'):
                    self.process_pem_cert(pem_rec, name, idx)
                elif pem_rec.startswith('-----BEGIN '):  # fallback
                    self.process_pem_rsakey(pem_rec, name, idx)

        except Exception as e:
            logger.debug('Exception processing PEM file %s : %s' % (name, e))
            self.trace_logger.log(e)

    def process_pem_cert(self, data, name, idx):
        """
        Processes PEM encoded certificate
        :param data:
        :param name:
        :param idx:
        :return:
        """
        from cryptography.x509.base import load_pem_x509_certificate
        try:
            x509 = load_pem_x509_certificate(data, self.get_backend())
            self.num_pem_certs += 1
            self.process_x509(x509, name=name, idx=idx, data=data, pem=True, source='pem-cert')

        except Exception as e:
            logger.debug('PEM processing failed: ' % e)
            self.trace_logger.log(e)

    def process_pem_rsakey(self, data, name, idx):
        """
        Processes PEM encoded RSA key
        :param data:
        :param name:
        :param idx:
        :return:
        """
        from Crypto.PublicKey import RSA
        try:
            rsa = RSA.importKey(data, passphrase=None)
            self.num_rsa_keys += 1
            self.num_rsa += 1

            if self.has_fingerprint(rsa.n):
                logger.warning('Fingerprint found in PEM RSA key %s ' % name)
                js = collections.OrderedDict()
                js['type'] = 'pem-rsa-key'
                js['fname'] = name
                js['idx'] = idx
                js['pem'] = data
                print(json.dumps(js))

        except Exception as e:
            logger.debug('Pubkey loading error: %s : %s [%s] : %s' % (name, idx, data[:20], e))
            self.trace_logger.log(e)

    def process_der(self, data, name):
        """
        DER processing
        :param data:
        :param name:
        :return:
        """
        from cryptography.x509.base import load_der_x509_certificate
        try:
            x509 = load_der_x509_certificate(data, self.get_backend())
            self.num_der_certs += 1
            self.process_x509(x509, name=name, pem=False, source='der-cert')

        except Exception as e:
            logger.debug('DER processing failed: %s : %s' % (name, e))
            self.trace_logger.log(e)

    def process_x509(self, x509, name, idx=None, data=None, pem=True, source='', aux=None):
        """
        Processing parsed X509 certificate
        :param x509:
        :param name:
        :param idx:
        :param data:
        :param pem:
        :param source:
        :param aux:
        :return:
        """
        if x509 is None:
            return

        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

        pub = x509.public_key()
        if not isinstance(pub, RSAPublicKey):
            return

        self.num_rsa += 1
        pubnum = x509.public_key().public_numbers()
        if self.has_fingerprint(pubnum.n):
            logger.warning('Fingerprint found in the Certificate %s idx %s ' % (name, idx))
            js = collections.OrderedDict()
            js['type'] = source
            js['fname'] = name
            js['idx'] = idx
            js['fprint'] = binascii.hexlify(x509.fingerprint(hashes.SHA256()))
            js['pem'] = data if pem else None
            js['aux'] = aux
            print(json.dumps(js))

    def process_pgp(self, data, name):
        """
        PGP key processing
        :param data:
        :param name:
        :return:
        """
        try:
            parts = re.split(r'-{5,}BEGIN', data)
            if len(parts) == 0:
                return

            if len(parts[0]) == 0:
                parts.pop(0)

            crt_arr = ['-----BEGIN' + x for x in parts]
            for idx, pem_rec in enumerate(crt_arr):
                try:
                    pem_rec = pem_rec.strip()
                    if len(pem_rec) == 0:
                        continue

                    self.process_pgp_raw(pem_rec, name, idx)

                except Exception as e:
                    logger.error('Exception in processing PGP rec file %s: %s' % (name, e))
                    self.trace_logger.log(e)

        except Exception as e:
            logger.error('Exception in processing PGP file %s: %s' % (name, e))
            self.trace_logger.log(e)

    def process_pgp_raw(self, data, name, file_idx=None):
        """
        Processes single PGP key
        :param data: file data
        :param name: file name
        :param file_idx: index in the file
        :return:
        """
        from pgpdump.data import AsciiData
        from pgpdump.packet import SignaturePacket, PublicKeyPacket, PublicSubkeyPacket, UserIDPacket

        js = collections.OrderedDict()

        pgp_key_data = AsciiData(data)
        packets = list(pgp_key_data.packets())
        self.num_pgp_masters += 1

        master_fprint = None
        master_key_id = None
        identities = []
        pubkeys = []
        sig_cnt = 0
        for idx, packet in enumerate(packets):
            if isinstance(packet, PublicKeyPacket):
                master_fprint = packet.fingerprint
                master_key_id = format_pgp_key(packet.key_id)
                pubkeys.append(packet)
            elif isinstance(packet, PublicSubkeyPacket):
                pubkeys.append(packet)
            elif isinstance(packet, UserIDPacket):
                identities.append(packet)
            elif isinstance(packet, SignaturePacket):
                sig_cnt += 1

        # Names / identities
        ids_arr = []
        identity = None
        for packet in identities:
            idjs = collections.OrderedDict()
            idjs['name'] = packet.user_name
            idjs['email'] = packet.user_email
            ids_arr.append(idjs)

            if identity is None:
                identity = '%s <%s>' % (packet.user_name, packet.user_email)

        js['type'] = 'pgp'
        js['fname'] = name
        js['fname_idx'] = file_idx
        js['identities'] = ids_arr
        js['signatures_count'] = sig_cnt
        js['packets_count'] = len(packets)
        js['keys_count'] = len(pubkeys)

        # Public keys processing
        for packet in pubkeys:
            try:
                self.num_pgp_total += 1
                if packet.modulus is None:
                    continue

                self.num_rsa += 1
                if self.has_fingerprint(packet.modulus):
                    js['created_at'] = self.strtime(packet.creation_time)
                    js['is_master'] = master_fprint == packet.fingerprint
                    js['kid'] = format_pgp_key(packet.key_id)
                    js['bitsize'] = packet.modulus_bitlen
                    js['master_kid'] = master_key_id
                    js['e'] = '0x%x' % packet.exponent
                    js['n'] = '0x%x' % packet.modulus
                    logger.warning('Fingerprint found in PGP key %s key ID 0x%s' % (name, js['kid']))
                    print(json.dumps(js))

            except Exception as e:
                logger.error('Excetion in processing the key: %s' % e)
                self.trace_logger.log(e)

    def process_ssh(self, data, name):
        """
        Processes SSH keys
        :param data:
        :param name:
        :return:
        """
        if data is None or len(data) == 0:
            return

        try:
            lines = [x.strip() for x in data.split('\n')]
            for idx, line in enumerate(lines):
                self.process_ssh_line(line, name, idx)

        except Exception as e:
            logger.debug('Exception in processing SSH public key %s : %s' % (name, e))
            self.trace_logger.log(e)

    def process_ssh_line(self, data, name, idx):
        """
        Processes single SSH key
        :param data:
        :param name:
        :param idx:
        :return:
        """
        data = data.strip()
        if 'ssh-rsa' not in data:
            return

        # strip ssh params / adjustments
        try:
            data = data[data.find('ssh-rsa'):]
        except:
            pass

        from cryptography.hazmat.primitives.serialization import load_ssh_public_key
        from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
        try:
            key_obj = load_ssh_public_key(data, self.get_backend())
            self.num_ssh += 1

            if not isinstance(key_obj, RSAPublicKey):
                return

            self.num_rsa += 1
            numbers = key_obj.public_numbers()

            if self.has_fingerprint(numbers.n):
                logger.warning('Fingerprint found in the SSH key %s idx %s ' % (name, idx))
                js = collections.OrderedDict()
                js['type'] = 'ssh-rsa'
                js['fname'] = name
                js['idx'] = idx
                js['mod'] = numbers.n
                js['ssh'] = data
                print(json.dumps(js))

        except Exception as e:
            logger.debug('Exception in processing SSH public key %s idx %s : %s' % (name, idx, e))
            self.trace_logger.log(e)

    def process_json(self, data, name):
        """
        Processes as a JSON
        :param data:
        :param name:
        :return:
        """
        if data is None or len(data) == 0:
            return

        try:
            lines = [x.strip() for x in data.split('\n')]
            for idx, line in enumerate(lines):
                self.process_json_line(line, name, idx)

        except Exception as e:
            logger.debug('Exception in processing JSON %s : %s' % (name, e))
            self.trace_logger.log(e)

    def process_json_line(self, data, name, idx):
        """
        Processes single json line
        :param data:
        :param name:
        :param idx:
        :return:
        """
        data = data.strip()
        if len(data) == 0:
            return

        try:
            js = json.loads(data)
            self.num_json += 1
            self.process_json_rec(js, name, idx, [])

        except Exception as e:
            logger.debug('Exception in processing JSON %s idx %s : %s' % (name, idx, e))
            self.trace_logger.log(e)

    def process_json_rec(self, data, name, idx, sub_idx):
        """
        Processes json rec - json object
        :param data:
        :param name:
        :param idx:
        :param sub_idx:
        :return:
        """
        if isinstance(data, types.ListType):
            for kidx, rec in enumerate(data):
                self.process_json_rec(rec, name, idx, list(sub_idx + [kidx]))
            return

        if isinstance(data, types.DictionaryType):
            for key in data:
                rec = data[key]
                self.process_json_rec(rec, name, idx, list(sub_idx + [rec]))

            if 'n' in data:
                self.process_js_mod(data['n'], name, idx, sub_idx)
            if 'mod' in data:
                self.process_js_mod(data['mod'], name, idx, sub_idx)

    def process_js_mod(self, data, name, idx, sub_idx):
        """
        Processes one moduli from JS
        :param data:
        :param name:
        :param idx:
        :param sub_idx:
        :return:
        """
        if isinstance(data, types.IntType):
            if self.has_fingerprint(data):
                logger.warning('Fingerprint found in json int modulus %s idx %s %s' % (name, idx, sub_idx))
                js = collections.OrderedDict()
                js['type'] = 'js-mod-num'
                js['fname'] = name
                js['idx'] = idx
                js['sub_idx'] = sub_idx
                js['mod'] = '%x' % data
                print(json.dumps(js))
            return

        self.process_mod_line(data, name, idx, aux={'stype': 'json', 'sub_idx': sub_idx})

    def process_apk(self, data, name):
        """
        Processes Android application
        :param data:
        :param name:
        :return:
        """
        from cryptography.x509.base import load_pem_x509_certificate
        from apk_parse.apk import APK
        try:
            apkf = APK(data, process_now=False, process_file_types=False, raw=True,
                       temp_dir=self.args.tmp_dir)
            apkf.process()
            self.num_apk += 1

            pem = apkf.cert_pem
            aux = {'subtype': 'apk'}

            x509 = load_pem_x509_certificate(pem, self.get_backend())

            self.process_x509(x509, name=name, idx=0, data=data, pem=True, source='apk-pem-cert', aux=aux)

        except Exception as e:
            logger.debug('Exception in processing JSON %s : %s' % (name, e))
            self.trace_logger.log(e)

    def process_mod(self, data, name):
        """
        Processing one modulus per line
        :param data:
        :param name:
        :return:
        """
        try:
            lines = [x.strip() for x in data.split('\n')]
            for idx, line in enumerate(lines):
                self.process_mod_line(line, name, idx)

        except Exception as e:
            logger.debug('Error in line mod file processing %s : %s' % (name, e))
            self.trace_logger.log(e)

    def process_mod_line(self, data, name, idx, aux=None):
        """
        Processes one line mod
        :param data:
        :param name:
        :param idx:
        :param aux:
        :return:
        """
        if data is None or len(data) == 0:
            return
        try:
            if self.args.key_fmt_base64 or re.match(r'^[a-zA-Z0-9+/=]+$', data):
                self.process_mod_line_num(data, name, idx, 'base64', aux)

            if self.args.key_fmt_hex or re.match(r'^(0x)?[a-fA-F0-9]+$', data):
                self.process_mod_line_num(data, name, idx, 'hex', aux)

            if self.args.key_fmt_dec or re.match(r'^[0-9]+$', data):
                self.process_mod_line_num(data, name, idx, 'dec', aux)

        except Exception as e:
            logger.debug('Error in line mod processing %s idx %s : %s' % (name, idx, e))
            self.trace_logger.log(e)

    def process_mod_line_num(self, data, name, idx, num_type='hex', aux=None):
        """
        Processes particular number
        :param data:
        :param name:
        :param idx:
        :param num_type:
        :param aux:
        :return:
        """
        try:
            num = 0
            if num_type == 'base64':
                num = int(base64.b16encode(base64.b64decode(data)), 16)
            elif num_type == 'hex':
                num = int(strip_hex_prefix(data), 16)
            elif num_type == 'dec':
                num = int(data)
            else:
                raise ValueError('Unknown number format: %s' % num_type)

            if self.has_fingerprint(num):
                logger.warning('Fingerprint found in modulus %s idx %s ' % (name, idx))
                js = collections.OrderedDict()
                js['type'] = 'mod-%s' % num_type
                js['fname'] = name
                js['idx'] = idx
                js['aux'] = aux
                js['mod'] = '%x' % num
                print(json.dumps(js))

        except Exception as e:
            logger.debug('Exception in testing modulus %s idx %s : %s data: %s' % (name, idx, e, data[:30]))
            self.trace_logger.log(e)

    def process_ldiff(self, data, name):
        """
        Processes LDAP output
        field;binary::blob
        :param data:
        :param name:
        :return:
        """
        from cryptography.x509.base import load_der_x509_certificate
        reg = re.compile(r'binary::\s*([0-9a-zA-Z+/=\s\t\r\n]{20,})$', re.MULTILINE | re.DOTALL)
        matches = re.findall(reg, data)

        num_certs_found = 0
        for idx, match in enumerate(matches):
            match = re.sub('[\r\t\n\s]', '', match)
            try:
                bindata = base64.b64decode(match)
                x509 = load_der_x509_certificate(bindata, self.get_backend())

                self.num_ldiff_cert += 1
                self.process_x509(x509, name=name, pem=False, source='ldiff-cert')

            except Exception as e:
                logger.debug('Error in line ldiff file processing %s, idx %s, matchlen %s : %s'
                             % (name, idx, len(match), e))
                self.trace_logger.log(e)

    #
    # Helpers & worker
    #

    def strtime(self, x):
        """
        Simple time format
        :param x:
        :return:
        """
        if x is None:
            return x
        return x.strftime('%Y-%m-%d')

    def get_backend(self, backend=None):
        """
        Default crypto backend
        :param backend:
        :return:
        """
        from cryptography.hazmat.backends import default_backend
        return default_backend() if backend is None else backend

    def work(self):
        """
        Entry point after argument processing.
        :return:
        """
        self.process_inputs()

        logger.info('### SUMMARY ####################')
        logger.info('Records tested: %s' % self.tested)
        logger.info('.. PEM certs: . . . %s' % self.num_pem_certs)
        logger.info('.. DER certs: . . . %s' % self.num_der_certs)
        logger.info('.. RSA key files: . %s' % self.num_rsa_keys)
        logger.info('.. PGP master keys: %s' % self.num_pgp_masters)
        logger.info('.. PGP total keys:  %s' % self.num_pgp_total)
        logger.info('.. SSH keys:  . . . %s' % self.num_ssh)
        logger.info('.. APK keys:  . . . %s' % self.num_apk)
        logger.info('.. JSON keys: . . . %s' % self.num_json)
        logger.info('.. LDIFF certs: . . %s' % self.num_ldiff_cert)
        logger.debug('. Total RSA keys . %s  (# of keys RSA extracted & analyzed)' % self.num_rsa)
        if self.found > 0:
            logger.info('Fingerprinted keys found: %s' % self.found)
            logger.info('WARNING: Potential vulnerability')
        else:
            logger.info('No fingerprinted keys found (OK)')
        logger.info('################################')

    def main(self):
        """
        Main entry point
        :return:
        """
        parser = argparse.ArgumentParser(description='Iont Fingerprinter')

        parser.add_argument('--tmp', dest='tmp_dir', default='.',
                            help='Temporary dir for subprocessing (e.g. APK parsing scratch)')

        parser.add_argument('--debug', dest='debug', default=False, action='store_const', const=True,
                            help='Debugging logging')

        parser.add_argument('--file-pem', dest='file_pem', default=False, action='store_const', const=True,
                            help='PEM encoded file')

        parser.add_argument('--file-der', dest='file_der', default=False, action='store_const', const=True,
                            help='DER encoded file')

        parser.add_argument('--file-pgp', dest='file_pgp', default=False, action='store_const', const=True,
                            help='PGP ASC encoded file')

        parser.add_argument('--file-ssh', dest='file_ssh', default=False, action='store_const', const=True,
                            help='SSH public key file')

        parser.add_argument('--file-mod', dest='file_mod', default=False, action='store_const', const=True,
                            help='One modulus per line')

        parser.add_argument('--file-json', dest='file_json', default=False, action='store_const', const=True,
                            help='JSON file')

        parser.add_argument('--file-ldiff', dest='file_ldiff', default=False, action='store_const', const=True,
                            help='LDIFF file')

        parser.add_argument('--key-fmt-base64', dest='key_fmt_base64', default=False, action='store_const', const=True,
                            help='Modulus per line, base64 encoded')

        parser.add_argument('--key-fmt-hex', dest='key_fmt_hex', default=False, action='store_const', const=True,
                            help='Modulus per line, hex encoded')

        parser.add_argument('--key-fmt-dec', dest='key_fmt_dec', default=False, action='store_const', const=True,
                            help='Modulus per line, dec encoded')

        parser.add_argument('files', nargs=argparse.ZERO_OR_MORE, default=[],
                            help='files to process')

        self.args = parser.parse_args()

        if self.args.debug:
            coloredlogs.install(level=logging.DEBUG, fmt=LOG_FORMAT)

        self.work()


def main():
    app = IontFingerprinter()
    app.main()


if __name__ == '__main__':
    main()

