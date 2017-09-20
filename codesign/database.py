#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Basic database methods / models for the project.
"""

from sqlalchemy import Column, DateTime, String, SmallInteger, Integer, ForeignKey, func, BLOB, Text, BigInteger
from sqlalchemy.orm import relationship, backref
from sqlalchemy.ext.declarative import declarative_base


Base = declarative_base()


class MavenSignature(Base):
    """
    Maven signature entity - stores single PGP signature for the Maven artifact
    """
    __tablename__ = 'maven_signature'
    id = Column(BigInteger, primary_key=True)

    group_id = Column(String(255), nullable=False,)
    artifact_id = Column(String(255), nullable=True)
    version_id = Column(String(255))

    date_discovered = Column(DateTime, default=func.now())
    date_last_check = Column(DateTime, default=func.now())
    sig_file = Column(BLOB, nullable=True)

    sig_hash = Column(String(64), nullable=True)
    sig_key_id = Column(String(64), nullable=True)
    sig_version = Column(Integer, nullable=True)
    sig_pub_alg = Column(String(64), nullable=True)
    sig_created = Column(DateTime, nullable=True)
    sig_expires = Column(DateTime, nullable=True)


class MavenArtifact(Base):
    """
    Base maven artifact - pom
    """
    __tablename__ = 'maven_artifact'
    id = Column(BigInteger, primary_key=True)

    group_id = Column(String(255), nullable=False, )
    artifact_id = Column(String(255), nullable=True)
    version_id = Column(String(255))

    date_discovered = Column(DateTime, default=func.now())
    date_last_check = Column(DateTime, default=func.now())
    pom_file = Column(BLOB, nullable=True)


class MavenArtifactIndex(Base):
    """
    Base maven artifact - versions
    """
    __tablename__ = 'maven_artifact_idx'
    id = Column(BigInteger, primary_key=True)

    group_id = Column(String(255), nullable=False, )
    artifact_id = Column(String(255), nullable=True)
    versions = Column(BLOB, nullable=True)

    date_discovered = Column(DateTime, default=func.now())
    date_last_check = Column(DateTime, default=func.now())


class PGPKey(Base):
    """
    Entity storing PGP keys
    """
    __tablename__ = 'pgp_key'
    id = Column(BigInteger, primary_key=True)
    key_id = Column(String(64), nullable=True)
    fingerprint = Column(String(255), nullable=True)
    key_file = Column(BLOB, nullable=True)

    date_last_check = Column(DateTime, nullable=True)
    date_downloaded = Column(DateTime, nullable=True)

    # In case of a sub-key
    master_key_id = Column(String(64), nullable=True)
    master_fingerprint = Column(String(255), nullable=True)
    master_key_file = Column(BLOB, nullable=True)

    date_created = Column(DateTime, nullable=True)
    date_expires = Column(DateTime, nullable=True)

    signatures_count = Column(Integer, nullable=True)
    identity = Column(Text, nullable=True)
    identity_name = Column(String(255), nullable=True)
    identity_email = Column(String(255), nullable=True)
    identities_json = Column(Text, nullable=True)

    key_type = Column(String(255), nullable=True)
    key_purpose = Column(String(32), nullable=True)
    key_version = Column(Integer, nullable=True)
    key_algorithm = Column(String(32), nullable=True)

    # RSA
    key_modulus = Column(Text, nullable=True)
    key_exponent = Column(Text, nullable=True)
    is_interesting = Column(Integer, nullable=False, default=0)

    # (EC)DSA
    prime = Column(Text, nullable=True)
    group_order = Column(Text, nullable=True)
    group_gen = Column(Text, nullable=True)
    key_value = Column(Text, nullable=True)


class GitHubKey(Base):
    """
    GitHub SSH auth keys
    """
    __tablename__ = 'github_key'
    id = Column(BigInteger, primary_key=True)
    text_raw = Column(Text)

    date_discovered = Column(DateTime, default=func.now())
    date_last_check = Column(DateTime, default=func.now())
    date_lost = Column(DateTime, default=None)

    key_id = Column(BigInteger, nullable=True)
    key_type = Column(String(32), nullable=True)
    key_modulus_hex = Column(Text, nullable=True)
    key_exponent_hex = Column(Text, nullable=True)
    key_exponent = Column(BigInteger, nullable=True)
    key_size = Column(Integer, nullable=True)
    is_interesting = Column(Integer, nullable=False, default=0)

    key_user_found = Column(String(255), nullable=True)
    key_user_id_found = Column(BigInteger, nullable=True)


class GitHubUser(Base):
    """
    GitHub users
    """
    __tablename__ = 'github_user'
    id = Column(BigInteger, primary_key=True)
    username = Column(String(255), nullable=False)
    date_discovered = Column(DateTime, default=func.now())
    date_last_check = Column(DateTime, default=func.now())
    usr_type = Column(Integer, nullable=True)


class GitHubUserKeys(Base):
    """
    GitHub SSH auth keys - user association
    """
    __tablename__ = 'github_user_key'
    id = Column(BigInteger, primary_key=True)
    user_id = Column(ForeignKey('github_user.id', name='fk_github_user_key_github_user_id', ondelete='CASCADE'),
                     nullable=False, index=True)
    key_id = Column(ForeignKey('github_key.id', name='fk_github_user_key_github_key_id', ondelete='CASCADE'),
                    nullable=False, index=True)
    fount_at = Column(DateTime, default=func.now(), nullable=True)
    lost_at = Column(DateTime, default=None, nullable=True)


class GitHubUserDetails(Base):
    """
    GitHub users
    """
    __tablename__ = 'github_user_details'
    id = Column(BigInteger, primary_key=True)
    username = Column(String(255), nullable=False)
    date_discovered = Column(DateTime, default=func.now())
    date_last_check = Column(DateTime, default=func.now())

    name = Column(String(255), nullable=True)
    company = Column(String(255), nullable=True)
    blog = Column(String(255), nullable=True)
    email = Column(String(255), nullable=True)
    bio = Column(Text, nullable=True)
    usr_type = Column(String(255), nullable=True)

    public_repos = Column(Integer, nullable=False, default=0)
    public_gists = Column(Integer, nullable=False, default=0)
    followers = Column(Integer, nullable=False, default=0)
    following = Column(Integer, nullable=False, default=0)

    created_at = Column(DateTime, nullable=True)
    updated_at = Column(DateTime, nullable=True)


class GitHubUserOrgs(Base):
    """
    GitHub users organisations
    """
    __tablename__ = 'github_user_orgs'
    id = Column(BigInteger, primary_key=True)
    username = Column(String(255), nullable=False)
    org_name = Column(String(255), nullable=False)
    org_id = Column(BigInteger, nullable=False)
    org_desc = Column(Text, nullable=True)
    date_discovered = Column(DateTime, default=func.now())
    date_last_check = Column(DateTime, default=func.now())


class GitHubRepo(Base):
    """
    Github repositories for the user
    """
    __tablename__ = 'github_repo'
    id = Column(BigInteger, primary_key=True)
    user_repo = Column(Integer, nullable=False, default=1)

    org_name = Column(String(255), nullable=True)
    username = Column(String(255), nullable=True)

    owner_id = Column(String(255), nullable=True)
    owner_login = Column(String(255), nullable=True)

    date_discovered = Column(DateTime, default=func.now())
    date_last_check = Column(DateTime, default=func.now())

    repo_name = Column(String(255), nullable=False)
    repo_stars = Column(Integer, nullable=False)
    repo_forks = Column(Integer, nullable=False)
    repo_watchers = Column(Integer, nullable=False)
    repo_is_fork = Column(Integer, nullable=False)
    repo_size = Column(Integer, nullable=False)
    repo_description = Column(Text, nullable=True)
    repo_homepage = Column(Text, nullable=True)
    repo_language = Column(String(255), nullable=True)

    repo_stargazers_url = Column(String(255), nullable=False)
    repo_forks_url = Column(String(255), nullable=False)

    created_at = Column(DateTime, nullable=True)
    updated_at = Column(DateTime, nullable=True)
    pushed_at = Column(DateTime, nullable=True)


class GitHubRepoColab(Base):
    """
    Github repositories colaborators
    """
    __tablename__ = 'github_repo_colab'
    id = Column(BigInteger, primary_key=True)

    repo_name = Column(String(255), nullable=False)
    user_name = Column(String(255), nullable=False)

    can_pull = Column(Integer, nullable=False)
    can_push = Column(Integer, nullable=False)
    can_admin = Column(Integer, nullable=False)


class GitHubRepoAssignee(Base):
    """
    Github repositories assignees
    """
    __tablename__ = 'github_repo_assignee'
    id = Column(BigInteger, primary_key=True)

    repo_name = Column(String(255), nullable=False)
    user_name = Column(String(255), nullable=False)


class AndroidApkMirrorApp(Base):
    """
    Androd application base
    """
    __tablename__ = 'android_apk_mirror_app'
    id = Column(BigInteger, primary_key=True)

    app_name = Column(String(255), nullable=True)
    package_name = Column(String(255), nullable=True, index=True)
    version_code = Column(String(255), nullable=True)
    version_number = Column(BigInteger, nullable=True)
    version_type = Column(String(255), nullable=True)
    version_variant = Column(String(255), nullable=True)

    date_discovered = Column(DateTime, default=func.now())
    date_last_check = Column(DateTime, default=func.now())

    company = Column(String(255), nullable=True)
    file_size = Column(BigInteger, nullable=True)
    downloads = Column(BigInteger, nullable=True)
    uploaded_at = Column(DateTime, default=None, nullable=True)

    processing_pid = Column(Integer, nullable=True)
    processing_started_at = Column(DateTime, default=None, nullable=True)  # reservation
    download_started_at = Column(DateTime, default=None, nullable=True)  # reservation
    processed_at = Column(DateTime, default=None, nullable=True)  # reservation
    downloaded_at = Column(DateTime, default=None, nullable=True)  # reservation
    is_processed = Column(SmallInteger, nullable=False, default=0)
    is_downloaded = Column(SmallInteger, nullable=False, default=0)

    url_detail = Column(Text, nullable=True)
    aux_json = Column(Text, nullable=True)


class AndroidApkMirrorApk(Base):
    """
    GitHub SSH auth keys
    """
    __tablename__ = 'android_apk_mirror_apk'
    id = Column(BigInteger, primary_key=True)
    app_id = Column(ForeignKey('android_apk_mirror_app.id', name='fk_android_apk_mirror_apk_android_apk_mirror_app_id',
                               ondelete='CASCADE'), nullable=False, index=True)
    app = relationship('AndroidApkMirrorApp', uselist=False)

    url_download = Column(Text, nullable=True)
    fpath = Column(Text, nullable=True)
    post_id = Column(BigInteger, nullable=True)

    date_discovered = Column(DateTime, default=func.now())
    date_last_check = Column(DateTime, default=func.now())
    date_lost = Column(DateTime, default=None)

    file_size = Column(BigInteger, nullable=True)
    md5 = Column(String(128), nullable=True)
    sha1 = Column(String(128), nullable=True)
    sha256 = Column(String(128), nullable=True)

    is_xapk = Column(SmallInteger, nullable=True)
    sub_apk_size = Column(BigInteger, nullable=True)

    apk_package = Column(String(255), nullable=True)
    apk_version_code = Column(String(255), nullable=True)
    apk_version_name = Column(String(255), nullable=True)
    apk_min_sdk = Column(String(128), nullable=True)
    apk_tgt_sdk = Column(String(128), nullable=True)
    apk_max_sdk = Column(String(128), nullable=True)

    sign_date = Column(DateTime, default=None)
    sign_info_cnt = Column(Integer, nullable=True)
    sign_serial = Column(String(255), nullable=True)
    sign_issuer = Column(Text, nullable=True)
    sign_alg = Column(String(64), nullable=True)
    sign_raw = Column(Text, nullable=True)

    cert_alg = Column(String(64), nullable=True)
    cert_fprint = Column(String(255), nullable=True)
    cert_not_before = Column(DateTime, default=None)
    cert_not_after = Column(DateTime, default=None)
    cert_dn = Column(Text, nullable=True)
    cert_issuer_dn = Column(Text, nullable=True)
    cert_raw = Column(Text, nullable=True)

    pub_type = Column(String(32), nullable=True)
    pub_modulus = Column(Text, nullable=True)
    pub_exponent = Column(Text, nullable=True)
    pub_modulus_size = Column(Integer, nullable=True)
    pub_interesting = Column(Integer, nullable=False, default=0)

    aux_json = Column(Text, nullable=True)


class AndroidApkPureApp(Base):
    """
    Androd application base
    """
    __tablename__ = 'android_apk_pure_app'
    id = Column(BigInteger, primary_key=True)

    app_name = Column(String(255), nullable=True)
    package_name = Column(String(255), nullable=True, index=True)
    version_code = Column(String(255), nullable=True)
    version_number = Column(BigInteger, nullable=True)
    version_type = Column(String(255), nullable=True)
    version_variant = Column(String(255), nullable=True)

    date_discovered = Column(DateTime, default=func.now())
    date_last_check = Column(DateTime, default=func.now())

    company = Column(String(255), nullable=True)
    file_size = Column(BigInteger, nullable=True)
    downloads = Column(BigInteger, nullable=True)
    uploaded_at = Column(DateTime, default=None, nullable=True)

    processing_pid = Column(Integer, nullable=True)
    processing_started_at = Column(DateTime, default=None, nullable=True)  # reservation
    download_started_at = Column(DateTime, default=None, nullable=True)  # reservation
    processed_at = Column(DateTime, default=None, nullable=True)  # reservation
    downloaded_at = Column(DateTime, default=None, nullable=True)  # reservation
    is_processed = Column(SmallInteger, nullable=False, default=0)
    is_downloaded = Column(SmallInteger, nullable=False, default=0)

    url_detail = Column(Text, nullable=True)
    aux_json = Column(Text, nullable=True)


class AndroidApkPureApk(Base):
    """
    GitHub SSH auth keys
    """
    __tablename__ = 'android_apk_pure_apk'
    id = Column(BigInteger, primary_key=True)
    app_id = Column(ForeignKey('android_apk_pure_app.id', name='fk_android_apk_pure_apk_android_apk_pure_app_id',
                               ondelete='CASCADE'), nullable=False, index=True)
    app = relationship('AndroidApkPureApp', uselist=False)

    url_download = Column(Text, nullable=True)
    fpath = Column(Text, nullable=True)
    post_id = Column(BigInteger, nullable=True)

    date_discovered = Column(DateTime, default=func.now())
    date_last_check = Column(DateTime, default=func.now())
    date_lost = Column(DateTime, default=None)

    file_size = Column(BigInteger, nullable=True)
    md5 = Column(String(128), nullable=True)
    sha1 = Column(String(128), nullable=True)
    sha256 = Column(String(128), nullable=True)

    is_xapk = Column(SmallInteger, nullable=True)
    sub_apk_size = Column(BigInteger, nullable=True)

    apk_package = Column(String(255), nullable=True)
    apk_version_code = Column(String(255), nullable=True)
    apk_version_name = Column(String(255), nullable=True)
    apk_min_sdk = Column(String(128), nullable=True)
    apk_tgt_sdk = Column(String(128), nullable=True)
    apk_max_sdk = Column(String(128), nullable=True)

    sign_date = Column(DateTime, default=None)
    sign_info_cnt = Column(Integer, nullable=True)
    sign_serial = Column(String(255), nullable=True)
    sign_issuer = Column(Text, nullable=True)
    sign_alg = Column(String(64), nullable=True)
    sign_raw = Column(Text, nullable=True)

    cert_alg = Column(String(64), nullable=True)
    cert_fprint = Column(String(255), nullable=True)
    cert_not_before = Column(DateTime, default=None)
    cert_not_after = Column(DateTime, default=None)
    cert_dn = Column(Text, nullable=True)
    cert_issuer_dn = Column(Text, nullable=True)
    cert_raw = Column(Text, nullable=True)

    pub_type = Column(String(32), nullable=True)
    pub_modulus = Column(Text, nullable=True)
    pub_exponent = Column(Text, nullable=True)
    pub_modulus_size = Column(Integer, nullable=True)
    pub_interesting = Column(Integer, nullable=False, default=0, index=True)

    aux_json = Column(Text, nullable=True)


class AndroidApkFilesApp(Base):
    """
    Androd application base
    """
    __tablename__ = 'android_apk_files_app'
    id = Column(BigInteger, primary_key=True)

    app_name = Column(String(255), nullable=True)
    package_name = Column(String(255), nullable=True, index=True)
    version_code = Column(String(255), nullable=True)
    version_number = Column(BigInteger, nullable=True)
    version_type = Column(String(255), nullable=True)
    version_variant = Column(String(255), nullable=True)

    date_discovered = Column(DateTime, default=func.now())
    date_last_check = Column(DateTime, default=func.now())

    company = Column(String(255), nullable=True)
    file_size = Column(BigInteger, nullable=True)
    downloads = Column(BigInteger, nullable=True)
    uploaded_at = Column(DateTime, default=None, nullable=True)

    processing_pid = Column(Integer, nullable=True)
    processing_started_at = Column(DateTime, default=None, nullable=True)  # reservation
    download_started_at = Column(DateTime, default=None, nullable=True)  # reservation
    processed_at = Column(DateTime, default=None, nullable=True)  # reservation
    downloaded_at = Column(DateTime, default=None, nullable=True)  # reservation
    is_processed = Column(SmallInteger, nullable=False, default=0)
    is_downloaded = Column(SmallInteger, nullable=False, default=0)

    url_detail = Column(Text, nullable=True)
    aux_json = Column(Text, nullable=True)


class AndroidApkFilesApk(Base):
    """
    GitHub SSH auth keys
    """
    __tablename__ = 'android_apk_files_apk'
    id = Column(BigInteger, primary_key=True)
    app_id = Column(ForeignKey('android_apk_files_app.id', name='fk_android_apk_files_apk_android_apk_files_app_id',
                               ondelete='CASCADE'), nullable=False, index=True)
    app = relationship('AndroidApkFilesApp', uselist=False)

    url_download = Column(Text, nullable=True)
    fpath = Column(Text, nullable=True)
    post_id = Column(BigInteger, nullable=True)

    date_discovered = Column(DateTime, default=func.now())
    date_last_check = Column(DateTime, default=func.now())
    date_lost = Column(DateTime, default=None)

    file_size = Column(BigInteger, nullable=True)
    md5 = Column(String(128), nullable=True)
    sha1 = Column(String(128), nullable=True)
    sha256 = Column(String(128), nullable=True)

    is_xapk = Column(SmallInteger, nullable=True)
    sub_apk_size = Column(BigInteger, nullable=True)

    apk_package = Column(String(255), nullable=True)
    apk_version_code = Column(String(255), nullable=True)
    apk_version_name = Column(String(255), nullable=True)
    apk_min_sdk = Column(String(128), nullable=True)
    apk_tgt_sdk = Column(String(128), nullable=True)
    apk_max_sdk = Column(String(128), nullable=True)

    sign_date = Column(DateTime, default=None)
    sign_info_cnt = Column(Integer, nullable=True)
    sign_serial = Column(String(255), nullable=True)
    sign_issuer = Column(Text, nullable=True)
    sign_alg = Column(String(64), nullable=True)
    sign_raw = Column(Text, nullable=True)

    cert_alg = Column(String(64), nullable=True)
    cert_fprint = Column(String(255), nullable=True)
    cert_not_before = Column(DateTime, default=None)
    cert_not_after = Column(DateTime, default=None)
    cert_dn = Column(Text, nullable=True)
    cert_issuer_dn = Column(Text, nullable=True)
    cert_raw = Column(Text, nullable=True)

    pub_type = Column(String(32), nullable=True)
    pub_modulus = Column(Text, nullable=True)
    pub_exponent = Column(Text, nullable=True)
    pub_modulus_size = Column(Integer, nullable=True)
    pub_interesting = Column(Integer, nullable=False, default=0)

    aux_json = Column(Text, nullable=True)

