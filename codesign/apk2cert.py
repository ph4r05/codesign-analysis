"""
Extract certificate stored in the APK as PEM
"""


import sys
import argparse
from apk_parse.apk import APK


def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Extracts PEM certificates from APK files')
    parser.add_argument('files', nargs=argparse.ZERO_OR_MORE, default=[], help='APK files')
    args = parser.parse_args()

    for file_name in args.files:
        apkf = APK(file_name)
        pem = apkf.cert_pem
        print(pem)


if __name__ == "__main__":
    main()


