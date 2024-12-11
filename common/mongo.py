# -*- coding: utf-8 -*-

from pymongo import MongoClient
from config import MONGO_URL, MONGO_DB


class ConnMongo(object):
    _instance = None

    def __new__(cls):
        if not cls._instance:
            cls._instance = super(ConnMongo, cls).__new__(cls)
            cls._instance.conn = MongoClient(MONGO_URL)
        return cls._instance


def conn_db(collection, db_name=None):
    conn = ConnMongo().conn
    if db_name:
        return conn[db_name][collection]

    else:
        return conn[MONGO_DB][collection]
