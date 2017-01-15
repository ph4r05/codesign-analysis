#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Parses maven signature file
"""


import os
import sys
import argparse
import inspect
import binascii
import logging
import coloredlogs
import gnupg
from pgpdump.data import AsciiData
from pgpdump.packet import SignaturePacket, PublicKeyPacket, PublicSubkeyPacket, UserIDPacket

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
    parser = argparse.ArgumentParser(description='Parses maven signature file')
    parser.add_argument('files', nargs=argparse.ZERO_OR_MORE, default=[], help='APK files')
    args = parser.parse_args()

    gpg = gnupg.GPG(gnupghome='~')
    gpg.encoding = 'utf-8'

    for file_name in args.files:
        data = open(file_name, 'r').read()
        pgp = AsciiData(data)
        packets = list(pgp.packets())
        sig_packet = packets[0]
        if isinstance(sig_packet, SignaturePacket):
            print('Hash alg: %s' % sig_packet.hash_algorithm)
            print('Key id: %s' % sig_packet.key_id)
            print('Sig type: %s' % sig_packet.sig_type)
            print('Sig version: %s' % sig_packet.sig_version)
            print('Pub algorithm: %s' % sig_packet.pub_algorithm)
            print('Creation date: %s' % sig_packet.creation_time)
            print('Expiration date: %s' % sig_packet.expiration_time)

            key = utils.get_pgp_key(sig_packet.key_id)
            pgp_key_data = AsciiData(key)
            packets = list(pgp_key_data.packets())
            print('Packets: %s' % len(packets))
            print('-' * 80)
            for idx, packet in enumerate(packets):
                if isinstance(packet, PublicKeyPacket): # PublicSubkeyPacket
                    print('Is subkey: %s' % isinstance(packet, PublicSubkeyPacket))
                    print('Algorithm: %s' % packet.pub_algorithm)
                    print('Pub key version: %s' % packet.pubkey_version)
                    print('Fingerprint: %s' % packet.fingerprint)
                    print('key_id: %s' % packet.key_id)
                    print('creation_time: %s' % packet.creation_time)
                    print('expiration_time: %s' % packet.expiration_time)
                    print('raw_days_valid: %s' % packet.raw_days_valid)
                    print('pub_algorithm_type: %s' % packet.pub_algorithm_type)
                    print('modulus: %s' % packet.modulus)
                    print('modulus_bitlen: %s' % packet.modulus_bitlen)
                    print('exponent: %s' % packet.exponent)
                    print('prime: %s' % packet.prime)
                    print('group_order: %s' % packet.group_order)
                    print('group_gen: %s' % packet.group_gen)
                    print('key_value: %s' % packet.key_value)
                    print('-' * 80)

                elif isinstance(packet, UserIDPacket):
                    print('User: %s' % packet.user)
                    print('User name: %s' % packet.user_name)
                    print('User email: %s' % packet.user_email)
                    print('-' * 80)
                # else:
                #     print(packet)
                #     print(packet.subpackets)
                #     print([x.data for x in packet.subpackets])









if __name__ == "__main__":
    main()


