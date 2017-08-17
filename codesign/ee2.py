#!/usr/bin/env python
# -*- coding: utf-8 -*-

import ldap, base64, textwrap, time, random, datetime
import logging
import coloredlogs

LDAP_SERVER = "ldap://ldap.sk.ee"

MID = "ESTEID (MOBIIL-ID)"
DIGI = "ESTEID (DIGI-ID)"
IDCARD = "ESTEID"
RESIDENT_DIGI = "ESTEID (DIGI-ID E-RESIDENT)"
RESIDENT_MID = "ESTEID (MOBIIL-ID E-RESIDENT)"

AUTH = "Authentication"
SIGN = "Digital Signature"

SLEEP_OK = 5
SLEEP_ERR = 60*10

_ = lambda x: x  # please copypaste from lib/libldap.py
logger = logging.getLogger(__name__)
coloredlogs.install(level=logging.DEBUG)


class LdapError(Exception):
    pass


def get_pems_from_ldap(idcode, cert_type, chip_type):
    """
    Fetches the certificate(s) of the idcode owner from SK LDAP.
    """
    assert idcode.isdigit() and len(idcode) == 11

    server = ldap.initialize(LDAP_SERVER)
    q = server.search('ou=%s,o=%s,c=EE' % (cert_type, chip_type), ldap.SCOPE_SUBTREE,
                      'serialNumber=%s' % idcode,
                      ['userCertificate;binary'])

    result = server.result(q, timeout=10)
    if result[0] != ldap.RES_SEARCH_RESULT:
        raise LdapError(_("Unexpected result type."))
    if not result[1]:
        raise LdapError(_("No results from LDAP query."))
    if len(result[1][0]) != 2 or not isinstance(result[1][0][1], dict) \
            or not result[1][0][1].has_key('userCertificate;binary') \
            or not result[1][0][1]['userCertificate;binary'] \
            or not isinstance(result[1][0][1]['userCertificate;binary'], list):
        raise LdapError(_("Unexpected result format."))
    return [_get_pem_from_der(x) for x in result[1][0][1]['userCertificate;binary']]


def _get_pem_from_der(der):
    """
    Converts DER certificate to PEM.
    """
    return "\n".join(("-----BEGIN CERTIFICATE-----",
        "\n".join(textwrap.wrap(base64.b64encode(der), 64)),
        "-----END CERTIFICATE-----",))


def random_isikukood():
    """
    Generates random personal code / isikukood
    :return:
    """
    century = 0  # random.randint(0, 1)
    sex = random.randint(3, 4)

    d1 = sex + century

    # year - century 0 -> live people.. start with 50
    #        century 1 -> adult people, none :P
    year = random.randint(50, 99)

    # generate random day & month in that year - ordinals
    minord = datetime.date(year=year, month=1, day=1).toordinal()
    maxord = datetime.date(year=year, month=12, day=31).toordinal()
    randord = random.randint(minord, maxord)
    rnddate = datetime.date.fromordinal(randord)

    # serial = random.randint(0, 999)
    serial = random.randint(1, 40)  # small serials

    code = '%d%02d%02d%02d%03d' % (d1, year, rnddate.month, rnddate.day, serial)
    return code + control_nr(code)


def control_nr(code):
    code = [int(i) for i in code]
    weight1 = [1, 2, 3, 4, 5, 6, 7, 8, 9, 1]
    weight2 = [3, 4, 5, 6, 7, 8, 9, 1, 2, 3]
    sum1 = sum([x*y for x,y in zip(code, weight1)])
    sum2 = sum([x*y for x,y in zip(code, weight2)])
    if sum1 % 11 != 10:
        return str(sum1 % 11)
    elif sum2 % 11 != 10:
        return str(sum2 % 11)
    else:
        return "0"


def append_to_file(id):
    with open('./eeids.txt', 'a+') as fh:
        fh.write('%s\n' % id)


def main():
    slp = SLEEP_OK
    hits = 0
    found = []

    for i in range(50000):
        id = random_isikukood()
        try:
            logger.debug('A : %d, c: %s, t: %s, hits: %s' % (i, id, time.time(), hits))

            res = get_pems_from_ldap(id, AUTH, IDCARD)
            logger.info('Success! Found: %s' % id)

            hits += 1
            found.append(id)
            append_to_file(id)

            time.sleep(slp)

        except Exception as e:
            if 'desc' in e.message and 'LDAP server' in e.message['desc']:
                logger.warning('LDAP server blocked')
                time.sleep(SLEEP_ERR)
                continue

            logger.debug('Exception: %s' % e)
            time.sleep(slp)


if __name__ == '__main__':
    print(main())

