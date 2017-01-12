#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Extract public modulus from the APK, prints it as hexa number
"""

from apk_parse.apk import APK
import argparse
from cryptography.hazmat.backends import default_backend
from cryptography.x509.base import load_pem_x509_certificate


def get_backend(backend=None):
    return default_backend() if backend is None else backend


def load_x509(data, backend=None):
    return load_pem_x509_certificate(data, get_backend(backend))


def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Extracts RSA modulus as a hexa string from APK files')
    parser.add_argument('files', nargs=argparse.ZERO_OR_MORE, default=[], help='APK files')
    args = parser.parse_args()

    for file_name in args.files:
        apkf = APK(file_name)
        pem = apkf.cert_pem

        x509 = load_x509(pem)
        pub = x509.public_key()
        n = pub.public_numbers().n
        print('%x' % n)


if __name__ == "__main__":
    main()

