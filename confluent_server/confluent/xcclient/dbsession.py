#!/usr/bin/env python
###############################################################################
# IBM(c) 2007 EPL license http://www.eclipse.org/legal/epl-v10.html
###############################################################################
# -*- coding: utf-8 -*-
#

from sqlalchemy import create_engine,inspect
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import re
import os
import sqlalchemy.exc
from exceptions import *
import codecs

codecs.register(lambda name: codecs.lookup('utf8') if name == 'utf8mb4' else None)

Base = declarative_base()
Base.metadata.bind = None;


class Singleton(object):
  def __new__(cls,*args,**kwargs):
    if not hasattr(cls,'_inst'):
      cls._inst=super(Singleton,cls).__new__(cls,*args,**kwargs)
    return cls._inst

class DBsession(Singleton):
    _dbcfgpath='/etc/xcat/cfgloc'
    _dbcfgregex=re.compile("^(\S+):dbname=(\S+);host=(\S+)\|(\S+)\|(\S*)$")

    def __init__(self):
        self._sessions={}

    def __del__(self):
        self.close()

    #check whether the backend db is sqlite
    @classmethod
    def isSqlite(cls):
        if os.path.exists(cls._dbcfgpath):
            return False
        else:
            return True

    #create DB engine according to the xcat cfgloc file 
    @classmethod
    def createEngine(cls,tablename=None):
        if not cls.isSqlite():
            dbcfgfile = open(cls._dbcfgpath)
            dbcfgloc = dbcfgfile.read( )
            dbcfgfile.close()
            try:
                (dbtype,dbname,dbhost,dbusername,dbpasswd)=re.findall(cls._dbcfgregex,dbcfgloc)[0]
            except:
                raise BadDBHdlException("Error: invalid cfgloc file: %(o)s", o=cls._dbcfgpath) 
            if dbtype == 'Pg':
                conn="postgresql+psycopg2://"
            elif dbtype == 'mysql':
                conn="mysql+pymysql://"
            engine_value = conn+dbusername+':'+dbpasswd+'@'+dbhost+'/'+dbname
        elif tablename:
            engine_value = 'sqlite:////etc/xcat/'+tablename+'.sqlite'
        else:
            raise BadDBHdlException("Error: table name not specified!") 
        engine=create_engine(engine_value, echo=False)
        return engine

    @classmethod
    def getEngine(cls,tablename=None):
        """"""
        if not cls.isSqlite():
            if not Base.metadata.bind:
                engine=cls.createEngine()
            else:
                return Base.metadata.bind
        elif tablename:
            engine=cls.createEngine(tablename)
        return engine

    #bind Base.metadata to db engine
    @classmethod
    def createSession(cls,tablename=None):
        """"""
        engine=cls.getEngine(tablename)
        #metadata = Base.metadata
        #print metadata.tables.keys()
        Session = sessionmaker(bind=engine)
        session = Session()
        return session


    #get db session
    def loadSession(self,tablename=None):
        if self.__class__.isSqlite():
            if tablename not in self._sessions.keys():
                session=self.__class__.createSession(tablename)
                if session:
                    self._sessions[tablename]=session
                return session
            else:
                return self._sessions[tablename]
        else:    
            if self._sessions:
                mykey=self._sessions.keys()[0]
                return self._sessions[mykey]
            else:
                session=self.__class__.createSession(tablename)
                self._sessions['_globaldbsession']=session
                return session
        
    #commit all the transactions 
    def commit(self):
        for session in self._sessions.keys():
            self._sessions[session].commit()
    #close all sessions
    def close(self):
        for session in self._sessions.keys():
            self._sessions[session].close()
            del self._sessions[session]
        
    #for debug: print the self._sessions
    def dumpsession(self):
        print(self._sessions)
 
if __name__ == "__main__":
    pass
