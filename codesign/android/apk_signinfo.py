#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Extract certificate stored in the APK as PEM
"""


import os
import sys
import argparse
import inspect
import binascii
import logging
import base64
import coloredlogs
from apk_parse.apk import APK
from pyx509.models import PKCS7, PKCS7_SignedData

currentdir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
parentdir = os.path.dirname(currentdir)
sys.path.insert(0, parentdir)

try:
    from codesign import utils
except:
    import utils


logger = logging.getLogger(__name__)
coloredlogs.install(level=logging.INFO)


def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Extracts Signing information from the APK')
    parser.add_argument('files', nargs=argparse.ZERO_OR_MORE, default=[], help='APK files')
    parser.add_argument('--der', dest='der', default=False, action='store_const', const=True,
                        help='DER only')
    args = parser.parse_args()

    for file_name in args.files:
        apkf = APK(file_name)
        pem = apkf.cert_pem

        der = apkf.pkcs7_der
        if args.der:
            sys.stdout.write(der)
            return

        print(pem)
        print(apkf.cert_text)

        p7 = PKCS7.from_der(der)
        try:
            signed_date, valid_from, valid_to, signer = p7.get_timestamp_info()
            print('Sign date: %s = %s' % (utils.unix_time_millis(signed_date), utils.fmt_time(signed_date)))
            print('Sign not before: %s = %s' % (utils.unix_time_millis(valid_from), utils.fmt_time(valid_from)))
            print('Sign not after: %s = %s' % (utils.unix_time_millis(valid_to), utils.fmt_time(valid_to)))
            print('Signer: %s' % str(signer))
        except Exception as e:
            logger.error('Error parsing signer info: %s' % e)

        if not isinstance(p7.content, PKCS7_SignedData):
            logger.info('Not a PKCS7 signed data')

        print('Signer info cnt: %s' % len(p7.content.signerInfos))
        if len(p7.content.signerInfos) > 0:
            signer_info = p7.content.signerInfos[0]
            print('Signer serial: %s' % signer_info.serial_number)
            print('Sign issuer: %s' % signer_info.issuer)
            print('Sign algorithm: %s' % signer_info.oid2name(signer_info.digest_algorithm))


if __name__ == "__main__":
    main()


