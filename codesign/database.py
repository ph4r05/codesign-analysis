#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Basic database methods / models for the project.
"""

from sqlalchemy import Column, DateTime, String, Integer, ForeignKey, func, BLOB, Text, BigInteger
from sqlalchemy.orm import relationship, backref
from sqlalchemy.ext.declarative import declarative_base


Base = declarative_base()


class MavenSignature(Base):
    """
    Maven signature entity - stores single PGP signature for the Maven artifact
    """
    __tablename__ = 'maven_signature'
    id = Column(Integer, primary_key=True)

    group_id = Column(String, nullable=False)
    artifact_id = Column(String, nullable=True)
    version_id = Column(String)

    date_last_check = Column(DateTime)
    sig_file = Column(BLOB, nullable=True)

    sig_hash = Column(String, nullable=True)
    sig_key_id = Column(String, nullable=True)
    sig_version = Column(Integer, nullable=True)
    sig_pub_alg = Column(String, nullable=True)
    sig_created = Column(DateTime, nullable=True)
    sig_expires = Column(DateTime, nullable=True)


class PGPKey(Base):
    """
    Entity storing PGP keys
    """
    __tablename__ = 'pgp_key'
    id = Column(Integer, primary_key=True)
    key_id = Column(String, nullable=True)
    fingerprint = Column(String, nullable=True)
    key_file = Column(BLOB, nullable=True)

    date_last_check = Column(DateTime, nullable=True)

    # In case of a sub-key
    master_key_id = Column(String, nullable=True)

    date_created = Column(DateTime, nullable=True)
    date_expires = Column(DateTime, nullable=True)

    signatures_count = Column(DateTime, nullable=True)
    identity_name = Column(String, nullable=True)
    identity_email = Column(String, nullable=True)
    identities_json = Column(Text, nullable=True)

    key_type = Column(String, nullable=True)
    key_purpose = Column(String, nullable=True)
    key_version = Column(Integer, nullable=True)
    key_algorithm = Column(String, nullable=True)

    # RSA
    key_modulus = Column(BigInteger, nullable=True)
    key_exponent = Column(BigInteger, nullable=True)

    # (EC)DSA
    prime = Column(BigInteger, nullable=True)
    group_order = Column(BigInteger, nullable=True)
    group_gen = Column(BigInteger, nullable=True)
    key_value = Column(BigInteger, nullable=True)


class GitHubKey(Base):
    """
    GitHub SSH auth keys
    """
    __tablename__ = 'github_key'
    id = Column(Integer, primary_key=True)
    text_raw = Column(Text)

    date_last_check = Column(DateTime)
    key_id = Column(Integer, unique=True)
    key_type = Column(String, nullable=True)
    key_modulus = Column(BigInteger, nullable=True)
    key_exponent = Column(BigInteger, nullable=True)

    key_user_found = Column(String, nullable=True)
    key_user_id_found = Column(Integer, nullable=True)

