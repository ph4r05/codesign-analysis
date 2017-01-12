#!/usr/bin/env python
# -*- coding: utf-8 -*-

import re
import datetime
import binascii
import traceback
import logging
from cryptography.hazmat.backends import default_backend
from cryptography.x509.base import load_pem_x509_certificate
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID


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
    return (dt - datetime.datetime.utcfromtimestamp(0)).total_seconds()


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


def extend_with_cert_data(rec, x509, logger=None):
    """
    Extends record with the X509 data
    :param rec:
    :param x509:
    :param logger:
    :return:
    """
    rec['cert_fprint'] = binascii.hexlify(x509.fingerprint(hashes.SHA256()))
    rec['cert_not_before'] = unix_time_millis(x509.not_valid_before)
    rec['cert_not_before_fmt'] = x509.not_valid_before.isoformat()
    rec['cert_not_after'] = unix_time_millis(x509.not_valid_after)
    rec['cert_not_after_fmt'] = x509.not_valid_after.isoformat()

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

