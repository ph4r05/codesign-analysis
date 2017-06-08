#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Key IONT fingerprinting
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

logger = logging.getLogger(__name__)
coloredlogs.install(level=logging.INFO)


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
        is_ssh_file = data.startswith('ssh-')
        is_pgp_file = data.startswith('-----BEGIN PGP')
        is_pem_file = data.startswith('-----BEGIN') and not is_pgp_file

        is_pgp = (self.file_matches_extensions(name, ['pgp', 'gpg', 'key', 'pub', 'asc'])
                  and not is_ssh_file
                  and not is_pem_file) \
                 or is_pgp_file
        is_pgp |= self.args.file_pgp

        is_crt_ext = self.file_matches_extensions(name, ['der', 'crt', 'cer', 'cert', 'x509', 'key', 'pub', 'ca'])

        is_pem = self.file_matches_extensions(name, 'pem') or is_pem_file
        is_pem |= self.args.file_pem

        is_der = not is_pem and not is_ssh_file and not is_pgp_file and is_crt_ext
        is_der |= self.args.file_der

        is_ssh = self.file_matches_extensions(name, ['ssh', 'pub']) or is_ssh_file
        is_ssh |= self.args.file_ssh

        is_mod = self.file_matches_extensions(name, ['txt', 'mod', 'mods', 'moduli'])
        is_mod |= not is_pem and not is_der and not is_pgp and not is_ssh_file
        is_mod |= self.args.file_mod

        det = is_pem or is_der or is_pgp or is_ssh or is_mod
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

        if is_mod:
            logger.debug('processing %s as MOD' % name)
            self.process_mod(data, name)

        if not det:
            logger.debug('Undetected (skipped) file: %s' % name)

    def process_pem(self, data, name):
        """
        PEM processing - splitting further by the type of the records
        :param data:
        :param name:
        :return:
        """
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
            self.process_x509(x509, name=name, idx=idx, data=data, pem=True)

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
            self.process_x509(x509, name=name, pem=False)

        except Exception as e:
            logger.debug('DER processing failed: %s : %s' % (name, e))
            self.trace_logger.log(e)

    def process_x509(self, x509, name, idx=None, data=None, pem=True):
        """
        Processing parsed X509 certificate
        :param x509:
        :param name:
        :param idx:
        :param data:
        :param pem:
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
            js['type'] = 'pem-cert' if pem else 'der-cert'
            js['fname'] = name
            js['idx'] = idx
            js['fprint'] = binascii.hexlify(x509.fingerprint(hashes.SHA256()))
            js['pem'] = data if pem else base64.b64encode(pem)
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
        if not data.startswith('ssh-rsa'):
            return

        from cryptography.hazmat.primitives.serialization import load_ssh_public_key
        from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
        try:
            key_obj = load_ssh_public_key(data, self.get_backend())
            self.num_ssh += 1

            if not isinstance(key_obj, RSAPublicKey):
                return

            numbers = key_obj.public_numbers()
            if self.has_fingerprint(numbers.n):
                self.num_rsa += 1
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

    def process_mod_line(self, data, name, idx):
        """
        Processes one line mod
        :param data:
        :param name:
        :param idx:
        :return:
        """
        if data is None or len(data) == 0:
            return
        try:
            if self.args.key_fmt_base64 or re.match(r'^[a-zA-Z0-9+/=]+$', data):
                self.process_mod_line_num(data, name, idx, 'base64')

            if self.args.key_fmt_hex or re.match(r'^[a-fA-F0-9]+$', data):
                self.process_mod_line_num(data, name, idx, 'hex')

            if self.args.key_fmt_dec or re.match(r'^[0-9]+$', data):
                self.process_mod_line_num(data, name, idx, 'dec')

        except Exception as e:
            logger.debug('Error in line mod processing %s idx %s : %s' % (name, idx, e))
            self.trace_logger.log(e)

    def process_mod_line_num(self, data, name, idx, num_type='hex'):
        """
        Processes particular number
        :param data:
        :param name:
        :param idx:
        :param num_type:
        :return:
        """
        try:
            num = 0
            if num_type == 'base64':
                num = int(base64.b16encode(base64.b64decode(data)), 16)
            elif num_type == 'hex':
                num = int(data, 16)
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
                js['mod'] = '%x' % num
                print(json.dumps(js))

        except Exception as e:
            logger.debug('Exception in testing modulus %s idx %s : %s' % (name, idx, e))
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
        logger.info('Records tested: %s, found: %s' % (self.tested, self.found))
        logger.info('.. PEM certs: . . . %s' % self.num_pem_certs)
        logger.info('.. DER certs: . . . %s' % self.num_der_certs)
        logger.info('.. RSA key files: . %s' % self.num_rsa_keys)
        logger.info('.. PGP master keys: %s' % self.num_pgp_masters)
        logger.info('.. PGP total keys:  %s' % self.num_pgp_total)
        logger.info('.. SSH keys:  . . . %s' % self.num_ssh)
        logger.info('.. Total RSA keys found: %s' % self.num_rsa)

    def main(self):
        """
        Main entry point
        :return:
        """
        parser = argparse.ArgumentParser(description='Iont Fingerprinter')

        parser.add_argument('--data', dest='data_dir', default='.',
                            help='Data directory output')

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
            coloredlogs.install(level=logging.DEBUG)

        self.work()


def main():
    app = IontFingerprinter()
    app.main()


if __name__ == '__main__':
    main()

