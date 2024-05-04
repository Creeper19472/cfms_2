# coding=utf-8
from __future__ import unicode_literals, absolute_import
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, String, VARCHAR, Text, Integer

ModelBase = declarative_base()  # <- MetaClass


class PathStructures(ModelBase):
    __tablename__ = "path_structures"

    id = Column(VARCHAR(255), primary_key=True)
    name = Column(Text())
    owner = Column(Text())
    parent_id = Column(VARCHAR(255))
    type = Column(Text())
    revisions = Column(Text())
    access_rules = Column(Text())
    external_access = Column(Text())
    properties = Column(Text())
    state = Column(Text())


class FileRevisions(ModelBase):
    __tablename__ = "file_revisions"

    rev_id = Column(VARCHAR(255), primary_key=True)
    parent_rev_id = Column(VARCHAR(255))
    path_id = Column(VARCHAR(255))
    created_time = Column(Integer())
    file_index_id = Column(VARCHAR(255))
    access_rules = Column(Text())
    external_access = Column(Text())
    state = Column(Integer())
    state_expire_time = Column(Integer())
