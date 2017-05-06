#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Basic maven classes / helpers
"""

from past.builtins import cmp, reduce
import types
import collections
import versions as vvs


class Artifact(object):
    """
    Base artifact for dependency computation, ignoring versions.
    """
    def __init__(self, grp=None, art=None, ver=None):
        """
        Initializes artifact object
        :param grp: 
        :param art: 
        :param ver: 
        """
        self.group = grp
        self.artifact = art
        self.version = ver

    def __cmp__(self, other):
        """
        Soft eq comparison, version is ignored.
        :param other: 
        :return: 
        """
        return cmp((self.group, self.artifact), (other.group, other.artifact))

    def __hash__(self):
        return hash((self.group, self.artifact))

    def __repr__(self):
        return 'Artifact(%r, %r, %r)' % (self.group, self.artifact, self.version)

    def to_json(self):
        js = collections.OrderedDict()
        js['group'] = self.group
        js['artifact'] = self.artifact
        js['version'] = self.version
        return js

    def to_ver(self):
        """
        Creates version artifact out of it
        :return: 
        """
        return ArtifactVer(self.group, self.artifact, self.version)

    def to_base(self):
        """
        Returns version irelevant version
        :return: 
        """
        return self


class ArtifactVer(Artifact):
    """
    Artifact for dependency computation, taking versions into consideration
    """

    def __cmp__(self, other):
        """
        Soft eq comparison, version is ignored.
        :param other: 
        :return: 
        """
        # if the other is just ordinary artifact, fallback to versionless comparison
        if isinstance(other, Artifact):
            return cmp((self.group, self.artifact),
                       (other.group, other.artifact))

        return cmp((self.group, self.artifact, vvs.Version(self.version)),
                   (other.group, other.artifact, vvs.Version(other.version)))

    def __hash__(self):
        return hash((self.group, self.artifact, self.version))

    def __repr__(self):
        return 'ArtifactVer(%r, %r, %r)' % (self.group, self.artifact, self.version)

    def to_ver(self):
        return self

    def to_base(self):
        Artifact(self.group, self.artifact, self.version)


class DepMapper(object):
    """
    Simple dependency mapper
    """
    def __init__(self):
        # DB:  artifact -> version map -> dependent project
        # DB stores association: library -> libraries dependent on the library
        self.db = collections.OrderedDict()

    def add_dependency(self, parent, dependency):
        """
        Adds a new dependency link to the mapper.
        :param parent: 
        :param dependency: 
        :return: 
        """
        if dependency not in self.db:
            self.db[dependency] = collections.OrderedDict()
        db_dep = self.db[dependency]

        if dependency.version not in db_dep:
            db_dep[dependency.version] = []

        db_dep[dependency.version].append(parent)

    def affected(self, artifacts):
        """
        Get tree of affected artifacts starting from the artifacts given
        :param artifacts: 
        :return: 
        """
        if not isinstance(artifacts, types.ListType):
            artifacts = [artifacts]

        ret = collections.OrderedDict()
        for artifact in artifacts:
            ret[artifact] = collections.OrderedDict()

        checked = set()
        cur_layer = ret

        # BFS
        while True:
            # For each artifact in the current layer the
            next_layer = collections.OrderedDict()
            num_added = 0

            for art in cur_layer:
                if art not in self.db:
                    continue  # no dependencies indexed
                if art.to_base() in checked:
                    continue  # already processed - loop avoidance

                rec = self.db[art]  # rec: ver -> [packages]
                flat = list(set(reduce(lambda x, y: x+y, [[]] + [rec[x] for x in rec])))
                for sub in flat:
                    sub = sub.to_base()
                    cur_layer[art][sub] = collections.OrderedDict()
                    next_layer[sub] = collections.OrderedDict()
                    num_added += 1

                checked.add(art.to_base())

            cur_layer = next_layer
            if num_added == 0:
                break

        return ret













