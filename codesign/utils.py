#!/usr/bin/env python
# -*- coding: utf-8 -*-

import re
import os
import datetime
import binascii
import traceback
import logging
import requests
import math
import json
import shutil
from lxml import html
from cryptography.hazmat.backends import default_backend
from cryptography.x509.base import load_pem_x509_certificate
from cryptography.hazmat.primitives.serialization import load_ssh_public_key
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID
from pyx509.models import PKCS7, PKCS7_SignedData


def slugify(value):
    """
    Normalizes string, converts to lowercase, removes non-alpha characters,
    and converts spaces to hyphens.
    """
    import unicodedata
    value = unicodedata.normalize('NFKD', value).encode('ascii', 'ignore')
    value = unicode(re.sub('[^\w\s\-.]', '', value).strip())
    value = unicode(re.sub('[-\s]+', '-', value))
    return value


def get_backend(backend=None):
    return default_backend() if backend is None else backend


def load_x509(data, backend=None):
    return load_pem_x509_certificate(data, get_backend(backend))


def unix_time_millis(dt):
    if dt is None:
        return None
    return (dt - datetime.datetime.utcfromtimestamp(0)).total_seconds()


def fmt_time(dt):
    if dt is None:
        return None
    return dt.isoformat()


def get_cn(obj):
    """Accepts requests cert"""
    if obj is None:
        return None
    if 'subject' not in obj:
        return None

    sub = obj['subject'][0]
    for x in sub:
        if x[0] == 'commonName':
            return x[1]

    return None


def get_alts(obj):
    """Accepts requests cert"""
    if obj is None:
        return []
    if 'subjectAltName' not in obj:
        return []

    buf = []
    for x in obj['subjectAltName']:
        if x[0] == 'DNS':
            buf.append(x[1])

    return buf


def get_dn_part(subject, oid=None):
    if subject is None:
        return None
    if oid is None:
        raise ValueError('Disobey wont be tolerated')

    for sub in subject:
        if oid is not None and sub.oid == oid:
            return sub.value


def extend_with_android_data(rec, apkf, logger=None):
    """
    Android related info (versions, SDKs)
    :param rec:
    :param apkf:
    :param logger:
    :return:
    """
    try:
        rec['apk_version_code'] = apkf.get_androidversion_code()
    except Exception as e:
        logger.error('Exception in parsing android related info: %s' % e)
    try:
        rec['apk_version_name'] = apkf.get_androidversion_name()
    except Exception as e:
        logger.error('Exception in parsing android related info: %s' % e)
    try:
        rec['apk_min_sdk'] = apkf.get_min_sdk_version()
    except Exception as e:
        logger.error('Exception in parsing android related info: %s' % e)
    try:
        rec['apk_tgt_sdk'] = apkf.get_target_sdk_version()
    except Exception as e:
        logger.error('Exception in parsing android related info: %s' % e)
    try:
        rec['apk_max_sdk'] = apkf.get_max_sdk_version()
    except Exception as e:
        logger.error('Exception in parsing android related info: %s' % e)


def extend_with_pkcs7_data(rec, p7der, logger=None):
    """
    Extends APK record with the PKCS7 related data.
    :param rec:
    :param p7der:
    :param logger:
    :return:
    """
    try:
        p7 = PKCS7.from_der(p7der)

        try:
            signed_date, valid_from, valid_to, signer = p7.get_timestamp_info()
            rec['sign_date'] = unix_time_millis(signed_date)
            rec['sign_date_fmt'] = fmt_time(signed_date)
        except Exception as e:
            logger.error('Exception in parsing PKCS7 signer: %s' % e)

        if not isinstance(p7.content, PKCS7_SignedData):
            return

        rec['sign_info_cnt'] = len(p7.content.signerInfos)
        if len(p7.content.signerInfos) > 0:
            signer_info = p7.content.signerInfos[0]
            rec['sign_serial'] = str(signer_info.serial_number)
            rec['sign_issuer'] = str(signer_info.issuer)
            rec['sign_alg'] = str(signer_info.oid2name(signer_info.digest_algorithm))

    except Exception as e:
        logger.error('Exception in parsing PKCS7: %s' % e)


def extend_with_cert_data(rec, x509, logger=None):
    """
    Extends record with the X509 data
    :param rec:
    :param x509:
    :param logger:
    :return:
    """
    try:
        rec['cert_fprint'] = binascii.hexlify(x509.fingerprint(hashes.SHA256()))
        rec['cert_not_before'] = unix_time_millis(x509.not_valid_before)
        rec['cert_not_before_fmt'] = fmt_time(x509.not_valid_before)
        rec['cert_not_after'] = unix_time_millis(x509.not_valid_after)
        rec['cert_not_after_fmt'] = fmt_time(x509.not_valid_after)
    except Exception as e2:
        if logger is not None:
            logger.error('Cert parsing exception %s' % e2)

    # Subject
    try:
        rec['cert_cn'] = get_dn_part(x509.subject, NameOID.COMMON_NAME)
    except Exception as e2:
        if logger is not None:
            logger.error('Cert parsing exception %s' % e2)

    try:
        rec['cert_loc'] = get_dn_part(x509.subject, NameOID.LOCALITY_NAME)
        rec['cert_org'] = get_dn_part(x509.subject, NameOID.ORGANIZATION_NAME)
        rec['cert_orgunit'] = get_dn_part(x509.subject, NameOID.ORGANIZATIONAL_UNIT_NAME)
    except Exception as e2:
        if logger is not None:
            logger.error('Cert parsing exception %s' % e2)

    # Issuer
    try:
        rec['cert_issuer_cn'] = get_dn_part(x509.issuer, NameOID.COMMON_NAME)
    except Exception as e2:
        if logger is not None:
            logger.error('Cert parsing exception %s' % e2)

    try:
        rec['cert_issuer_loc'] = get_dn_part(x509.issuer, NameOID.LOCALITY_NAME)
        rec['cert_issuer_org'] = get_dn_part(x509.issuer, NameOID.ORGANIZATION_NAME)
        rec['cert_issuer_orgunit'] = get_dn_part(x509.issuer, NameOID.ORGANIZATIONAL_UNIT_NAME)
    except Exception as e2:
        if logger is not None:
            logger.error('Cert parsing exception %s' % e2)


def get_pgp_key(key_id, attempts=3, timeout=20, logger=None):
    """
    Simple PGP key getter - tries to fetch given key from the key server
    :param id:
    :return:
    """
    if not key_id.startswith('0x'):
        key_id = '0x' + key_id

    res = requests.get('https://pgp.mit.edu/pks/lookup?op=get&search=%s' % key_id, timeout=20)
    if math.floor(res.status_code / 100) != 2.0:
        res.raise_for_status()

    data = res.content
    if data is None:
        raise Exception('Empty response')

    tree = html.fromstring(data)
    txt = tree.xpath('//pre/text()')
    if len(txt) > 0:
        return txt[0].strip()

    return None


def flush_json(js, filepath):
    """
    Flushes JSON state file / configuration to the file name using move strategy
    :param js:
    :param filepath:
    :return:
    """
    abs_filepath = os.path.abspath(filepath)
    tmp_filepath = abs_filepath + '.tmpfile'
    with open(tmp_filepath, 'w') as fw:
        json.dump(js, fp=fw, indent=2)
        fw.flush()

    shutil.move(tmp_filepath, abs_filepath)


def load_ssh_pubkey(key_data):
    """
    Loads SH public key
    :param key_data:
    :return:
    """
    return load_ssh_public_key(key_data, get_backend())



