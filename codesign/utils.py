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
from cryptography.x509.oid import ExtensionOID
from cryptography import x509 as x509_c

from pyx509.models import PKCS7, PKCS7_SignedData
import errno
import logging
import stat
import subprocess
import shutil
import pwd
import grp
import types
import binascii
from datetime import datetime
import dateutil.parser
import time


logger = logging.getLogger(__name__)


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


def unix_time(dt):
    if dt is None:
        return None
    return (dt - datetime.utcfromtimestamp(0).replace(tzinfo=dt.tzinfo)).total_seconds()


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


def run_script(params, shell=False):
    """Run the script with the given params.

    :param list params: List of parameters to pass to Popen

    """
    try:
        proc = subprocess.Popen(params, shell=shell,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)

    except (OSError, ValueError):
        msg = "Unable to run the command: %s" % " ".join(params)
        logger.error(msg)
        raise Exception(msg)

    stdout, stderr = proc.communicate()

    if proc.returncode != 0:
        msg = "Error while running %s.\n%s\n%s" % (
            " ".join(params), stdout, stderr)
        # Enter recovery routine...
        logger.error(msg)
        raise Exception(msg)

    return stdout, stderr


def exe_exists(exe):
    """Determine whether path/name refers to an executable.

    :param str exe: Executable path or name

    :returns: If exe is a valid executable
    :rtype: bool

    """

    def is_exe(path):
        """Determine if path is an exe."""
        return os.path.isfile(path) and os.access(path, os.X_OK)

    path, _ = os.path.split(exe)
    if path:
        return is_exe(exe)
    else:
        for path in os.environ["PATH"].split(os.pathsep):
            if is_exe(os.path.join(path, exe)):
                return True

    return False


def make_or_verify_dir(directory, mode=0o755, uid=0, strict=False):
    """Make sure directory exists with proper permissions.

    :param str directory: Path to a directory.
    :param int mode: Directory mode.
    :param int uid: Directory owner.
    :param bool strict: require directory to be owned by current user

    :raises .errors.Error: if a directory already exists,
        but has wrong permissions or owner

    :raises OSError: if invalid or inaccessible file names and
        paths, or other arguments that have the correct type,
        but are not accepted by the operating system.

    """
    try:
        os.makedirs(directory, mode)
    except OSError as exception:
        if exception.errno == errno.EEXIST:
            if strict and not check_permissions(directory, mode, uid):
                raise Exception(
                    "%s exists, but it should be owned by user %d with"
                    "permissions %s" % (directory, uid, oct(mode)))
        else:
            raise


def check_permissions(filepath, mode, uid=0):
    """Check file or directory permissions.

    :param str filepath: Path to the tested file (or directory).
    :param int mode: Expected file mode.
    :param int uid: Expected file owner.

    :returns: True if `mode` and `uid` match, False otherwise.
    :rtype: bool

    """
    file_stat = os.stat(filepath)
    return stat.S_IMODE(file_stat.st_mode) == mode and file_stat.st_uid == uid


def chown(path, user, group=None, follow_symlinks=False):
    """
    Changes the ownership of the path.
    :param path:
    :param user:
    :param group:
    :return:
    """
    if group is None:
        group = user

    uid = pwd.getpwnam(user).pw_uid
    gid = grp.getgrnam(group).gr_gid
    os.chown(path, uid, gid)


def file_backup(path, chmod=0o644, backup_dir=None):
    """
    Backup the given file by copying it to a new file
    Copy is preferred to move. Move can keep processes working with the opened file after move operation.

    :param path:
    :param chmod:
    :param backup_dir:
    :return:
    """
    backup_path = None
    if os.path.exists(path):
        backup_path = path
        if backup_dir is not None:
            opath, otail = os.path.split(path)
            backup_path = os.path.join(backup_dir, otail)

        if chmod is None:
            chmod = os.stat(path).st_mode & 0o777

        with open(path, 'r') as src:
            fhnd, fname = unique_file(backup_path, chmod)
            with fhnd:
                shutil.copyfileobj(src, fhnd)
                backup_path = fname
    return backup_path


def dir_backup(path, chmod=0o644, backup_dir=None):
    """
    Backup the given directory
    :param path:
    :param chmod:
    :param backup_dir:
    :return:
    """
    backup_path = None
    if os.path.exists(path):
        backup_path = path
        if backup_dir is not None:
            opath, otail = os.path.split(path)
            backup_path = os.path.join(backup_dir, otail)

        if chmod is None:
            chmod = os.stat(path).st_mode & 0o777

        backup_path = safe_new_dir(backup_path, mode=chmod)
        os.rmdir(backup_path)
        shutil.copytree(path, backup_path)
    return backup_path


def delete_file_backup(path, chmod=0o644, backup_dir=None):
    """
    Backup the current file by moving it to a new file
    :param path:
    :param chmod:
    :param backup_dir:
    :return:
    """
    backup_path = None
    if os.path.exists(path):
        backup_path = file_backup(path, chmod=chmod, backup_dir=backup_dir)
        os.remove(path)
    return backup_path


def safe_create_with_backup(path, mode='w', chmod=0o644):
    """
    Safely creates a new file, backs up the old one if existed
    :param path:
    :param mode:
    :param chmod:
    :return:
    """
    backup_path = delete_file_backup(path, chmod)
    return safe_open(path, mode, chmod), backup_path


def safe_open(path, mode="w", chmod=None, buffering=None):
    """Safely open a file.

    :param str path: Path to a file.
    :param str mode: Same os `mode` for `open`.
    :param int chmod: Same as `mode` for `os.open`, uses Python defaults
        if ``None``.
    :param int buffering: Same as `bufsize` for `os.fdopen`, uses Python
        defaults if ``None``.

    """
    # pylint: disable=star-args
    open_args = () if chmod is None else (chmod,)
    fdopen_args = () if buffering is None else (buffering,)
    return os.fdopen(
        os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR, *open_args),
        mode, *fdopen_args)


def safe_new_dir(path, mode=0o755):
    """
    Creates a new unique directory. If the given directory already exists,
    linear incrementation is used to create a new one.


    :param path:
    :param mode:
    :return:
    """
    path, tail = os.path.split(path)
    return _unique_dir(
        path, dirname_pat=(lambda count: "%s_%04d" % (tail, count)),
        count=0, mode=mode)


def _unique_dir(path, dirname_pat, count, mode):
    while True:
        current_path = os.path.join(path, dirname_pat(count))
        try:
            os.makedirs(current_path, mode)
            return os.path.abspath(current_path)

        except OSError as exception:
            # "Dir exists," is okay, try a different name.
            if exception.errno != errno.EEXIST:
                raise
        count += 1


def _unique_file(path, filename_pat, count, mode):
    while True:
        current_path = os.path.join(path, filename_pat(count))
        try:
            return safe_open(current_path, chmod=mode), \
                   os.path.abspath(current_path)
        except OSError as err:
            # "File exists," is okay, try a different name.
            if err.errno != errno.EEXIST:
                raise
        count += 1


def unique_file(path, mode=0o777):
    """Safely finds a unique file.

    :param str path: path/filename.ext
    :param int mode: File mode

    :returns: tuple of file object and file name

    """
    path, tail = os.path.split(path)
    filename, extension = os.path.splitext(tail)
    return _unique_file(
        path, filename_pat=(lambda count: "%s_%04d%s" % (filename, count, extension if not None else '')),
        count=0, mode=mode)


def unique_lineage_name(path, filename, mode=0o777):
    """Safely finds a unique file using lineage convention.

    :param str path: directory path
    :param str filename: proposed filename
    :param int mode: file mode

    :returns: tuple of file object and file name (which may be modified
        from the requested one by appending digits to ensure uniqueness)

    :raises OSError: if writing files fails for an unanticipated reason,
        such as a full disk or a lack of permission to write to
        specified location.

    """
    preferred_path = os.path.join(path, "%s.conf" % (filename))
    try:
        return safe_open(preferred_path, chmod=mode), preferred_path
    except OSError as err:
        if err.errno != errno.EEXIST:
            raise
    return _unique_file(
        path, filename_pat=(lambda count: "%s-%04d.conf" % (filename, count)),
        count=1, mode=mode)


def safely_remove(path):
    """Remove a file that may not exist."""
    try:
        os.remove(path)
    except OSError as err:
        if err.errno != errno.ENOENT:
            raise


def get_file_mtime(file):
    return os.path.getmtime(file)


def get_utc_sec():
    return time.time()


def silent_close(c):
    try:
        if c is not None:
            c.close()
    except:
        pass


def strip(x):
    """
    Strips string x (if non empty) or each string in x if it is a list
    :param x:
    :return:
    """
    if x is None:
        return None
    if isinstance(x, types.ListType):
        return [y.strip() if y is not None else y for y in x]
    else:
        return x.strip()


def defval(val, default=None):
    """
    Returns val if is not None, default instead
    :param val:
    :param default:
    :return:
    """
    return val if val is not None else default


def defvalkey(js, key, default=None, take_none=True):
    """
    Returns js[key] if set, otherwise default. Note js[key] can be None.
    :param js:
    :param key:
    :param default:
    :param take_none:
    :return:
    """
    if key not in js:
        return default
    if js[key] is None and not take_none:
        return default
    return js[key]


def defvalkeys(js, key, default=None):
    """
    Returns js[key] if set, otherwise default. Note js[key] can be None.
    Key is array of keys. js[k1][k2][k3]...
     
    :param js:
    :param key:
    :param default:
    :param take_none:
    :return:
    """
    try:
        cur = js
        for ckey in key:
            cur = cur[ckey]
        return cur
    except:
        pass
    return default


def touch(fname, times=None):
    """
    Touches the file
    :param fname:
    :param times:
    :return:
    """
    with open(fname, 'a') as fhandle:
        os.utime(fname, times)


def try_touch(fname, times=None):
    """
    Touches the file, supress exception
    :param fname:
    :param times:
    :return:
    """
    try:
        touch(fname, times=times)
    except:
        pass


def try_get_san(cert):
    """
    Tries to load SAN from the certificate
    :param cert: 
    :return: 
    """
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        if ext is not None:
            values = list(ext.value.get_values_for_type(x509_c.DNSName))
            return values
    except:
        pass

    return []


def try_get_cname(cert):
    """
    Cname
    :param cert: 
    :return: 
    """
    try:
        return get_dn_part(cert.subject, NameOID.COMMON_NAME)
    except:
        pass
    return None


def try_parse_timestamp(x):
    """
    Tries to parse timestamp
    :param str: 
    :return: 
    """
    try:
        return dateutil.parser.parse(x)
    except:
        pass
    return None


def set_nonempty(dest, key, val):
    """
    Sets dest[key] = val if val is not none
    :param dest: 
    :param key: 
    :param val: 
    :return: 
    """
    if val is None:
        return
    dest[key] = val


