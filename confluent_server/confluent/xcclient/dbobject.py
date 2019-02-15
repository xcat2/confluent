#!/usr/bin/python
from dbsession import *
from copy import *
from sqlalchemy import inspect
import pdb

class mixin(object):
    def getdict(self):
        mydict={}
        for mykey in self.__dict__.keys():
           if mykey in self.__table__.columns:
              mydict[self.__tablename__+'.'+mykey.encode()]= self.__dict__[mykey] if self.__dict__[mykey] is None else self.__dict__[mykey].encode()
        try:
            self.__class__.outprocess(mydict)
        except:
            pass 
        return mydict

    #return a tuple of table primary keys
    @classmethod
    def primkeys(cls):
        ins = inspect(cls)
        prikeys=[ item.key for item in ins.primary_key ]
        prikeys.sort(None,None,reverse=False)
        return tuple(prikeys)

    #return the key of object in table row
    @classmethod
    def getobjkey(cls):
        return cls.primkeys()

    @classmethod
    def isValid(cls, netname, tabdict):
        return True

    @classmethod
    def dict2tabentry(self,objdict):
        pass      
    
    @classmethod
    def getcolumns(self):
        return self.__table__.columns.keys()

    @classmethod
    def getTabtype(self):
        return 'matrix'

    @classmethod
    def getReservedKeys(self):
        return []
########################################################################
class passwd(Base,mixin):
    """"""
    Base.metadata.bind = DBsession.getEngine('passwd')
    __tablename__ = 'passwd'
    __table_args__ = {'autoload':True}

    @classmethod
    def primkeys(cls):
        return ('key','username')

    @classmethod
    def getobjkey(cls):
        return tuple(['key'])
    
########################################################################
class networks(Base,mixin):
    """"""
    Base.metadata.bind = DBsession.getEngine('networks')
    __tablename__ = 'networks'
    __table_args__ = {'autoload':True}

    @classmethod
    def primkeys(cls):
        return tuple(['netname'])
    @classmethod
    def getobjkey(cls):
        return tuple(['netname'])

    @classmethod    
    def isValid(cls, netname, tabdict):
        eptkey=0
        if 'net' not in tabdict.keys() or not tabdict['net']:
            print("Error: net value should not be empty for xCAT network object "+netname)
            eptkey=1
        if 'mask' not in tabdict.keys() or not tabdict['mask']:
            print ("Error: mask value should not be empty for xCAT network object "+netname)
            eptkey=1
        if eptkey:
            return False
        else:
            return True

########################################################################
class routes(Base,mixin):
    """"""
    Base.metadata.bind = DBsession.getEngine('routes')
    __tablename__ = 'routes'
    __table_args__ = {'autoload':True}


########################################################################
class nodetype(Base,mixin):
    """"""
    Base.metadata.bind = DBsession.getEngine('nodetype')
    __tablename__ = 'nodetype'
    __table_args__ = {'autoload':True} 

########################################################################
'''
class hosts(Base,mixin):
    """"""
    __tablename__ = 'hosts'
    __table_args__ = {'autoload':True}
'''
########################################################################
class noderes(Base,mixin):
    """"""
    Base.metadata.bind = DBsession.getEngine('noderes')
    __tablename__ = 'noderes'
    __table_args__ = {'autoload':True}

########################################################################
class switch(Base,mixin):
    """"""
    Base.metadata.bind = DBsession.getEngine('switch')
    __tablename__ = 'switch'
    __table_args__ = {'autoload':True}

    @classmethod
    def getobjkey(cls):
        return tuple(['node'])
########################################################################
class switches(Base,mixin):
    """"""
    Base.metadata.bind = DBsession.getEngine('switches')
    __tablename__ = 'switches'
    __table_args__ = {'autoload':True}


########################################################################
class mac(Base,mixin):
    """"""
    Base.metadata.bind = DBsession.getEngine('mac')
    __tablename__ = 'mac'
    __table_args__ = {'autoload':True}
########################################################################
class hwinv(Base,mixin):
    """"""
    Base.metadata.bind = DBsession.getEngine('hwinv')
    __tablename__ = 'hwinv'
    __table_args__ = {'autoload':True}
########################################################################
class postscripts(Base,mixin):
    """"""
    Base.metadata.bind = DBsession.getEngine('postscripts')
    __tablename__ = 'postscripts'
    __table_args__ = {'autoload':True}

    @classmethod
    def getReservedKeys(self):
        return ('xcatdefaults','service')
    
########################################################################
class bootparams(Base,mixin):
    """"""
    Base.metadata.bind = DBsession.getEngine('bootparams')
    __tablename__ = 'bootparams'
    __table_args__ = {'autoload':True}

########################################################################
class nodelist(Base,mixin):
    """"""
    Base.metadata.bind = DBsession.getEngine('nodelist')
    __tablename__ = 'nodelist'
    __table_args__ = {'autoload':True}

########################################################################
class vm(Base,mixin):
    """"""
    Base.metadata.bind = DBsession.getEngine('vm')
    __tablename__ = 'vm'
    __table_args__ = {'autoload':True}
########################################################################
class policy(Base,mixin):
    """"""
    Base.metadata.bind = DBsession.getEngine('policy')
    __tablename__ = 'policy'
    __table_args__ = {'autoload':True}

########################################################################
class nodehm(Base,mixin):
    """"""
    Base.metadata.bind = DBsession.getEngine('nodehm')
    __tablename__ = 'nodehm'
    __table_args__ = {'autoload':True}
########################################################################
class nodegroup(Base,mixin):
    """"""
    Base.metadata.bind = DBsession.getEngine('nodegroup')
    __tablename__ = 'nodegroup'
    __table_args__ = {'autoload':True}
########################################################################
class vpd(Base,mixin):
    """"""
    Base.metadata.bind = DBsession.getEngine('vpd')
    __tablename__ = 'vpd'
    __table_args__ = {'autoload':True}
########################################################################
class servicenode(Base,mixin):
    """"""
    Base.metadata.bind = DBsession.getEngine('servicenode')
    __tablename__ = 'servicenode'
    __table_args__ = {'autoload':True}
########################################################################
class hosts(Base,mixin):
    """"""
    Base.metadata.bind = DBsession.getEngine('hosts')
    __tablename__ = 'hosts'
    __table_args__ = {'autoload':True}
########################################################################
class nics(Base,mixin):
    """"""
    Base.metadata.bind = DBsession.getEngine('nics')
    __tablename__ = 'nics'
    __table_args__ = {'autoload':True}
########################################################################
class openbmc(Base,mixin):
    """"""
    Base.metadata.bind = DBsession.getEngine('openbmc')
    __tablename__ = 'openbmc'
    __table_args__ = {'autoload':True}
########################################################################
class prodkey(Base,mixin):
    """"""
    Base.metadata.bind = DBsession.getEngine('prodkey')
    __tablename__ = 'prodkey'
    __table_args__ = {'autoload':True}

    @classmethod
    def getobjkey(cls):
        return tuple(['node'])
########################################################################
class domain(Base,mixin):
    """"""
    Base.metadata.bind = DBsession.getEngine('domain')
    __tablename__ = 'domain'
    __table_args__ = {'autoload':True}
########################################################################
class chain(Base,mixin):
    """"""
    Base.metadata.bind = DBsession.getEngine('chain')
    __tablename__ = 'chain'
    __table_args__ = {'autoload':True}
########################################################################
class rack(Base,mixin):
    """"""
    Base.metadata.bind = DBsession.getEngine('rack')
    __tablename__ = 'rack'
    __table_args__ = {'autoload':True}
########################################################################
class nodepos(Base,mixin):
    """"""
    Base.metadata.bind = DBsession.getEngine('nodepos')
    __tablename__ = 'nodepos'
    __table_args__ = {'autoload':True}
########################################################################
class ppc(Base,mixin):
    """"""
    Base.metadata.bind = DBsession.getEngine('ppc')
    __tablename__ = 'ppc'
    __table_args__ = {'autoload':True}
########################################################################
class ppchcp(Base,mixin):
    """"""
    Base.metadata.bind = DBsession.getEngine('ppchcp')
    __tablename__ = 'ppchcp'
    __table_args__ = {'autoload':True}
########################################################################
class mp(Base,mixin):
    """"""
    Base.metadata.bind = DBsession.getEngine('mp')
    __tablename__ = 'mp'
    __table_args__ = {'autoload':True}
########################################################################
class zvm(Base,mixin):
    """"""
    Base.metadata.bind = DBsession.getEngine('zvm')
    __tablename__ = 'zvm'
    __table_args__ = {'autoload':True}
########################################################################
class mpa(Base,mixin):
    """"""
    Base.metadata.bind = DBsession.getEngine('mpa')
    __tablename__ = 'mpa'
    __table_args__ = {'autoload':True}
########################################################################
class pdu(Base,mixin):
    """"""
    Base.metadata.bind = DBsession.getEngine('pdu')
    __tablename__ = 'pdu'
    __table_args__ = {'autoload':True}
########################################################################
class pduoutlet(Base,mixin):
    """"""
    Base.metadata.bind = DBsession.getEngine('pduoutlet')
    __tablename__ = 'pduoutlet'
    __table_args__ = {'autoload':True}
########################################################################
class cfgmgt(Base,mixin):
    """"""
    Base.metadata.bind = DBsession.getEngine('cfgmgt')
    __tablename__ = 'cfgmgt'
    __table_args__ = {'autoload':True}
########################################################################
class hypervisor(Base,mixin):
    """"""
    Base.metadata.bind = DBsession.getEngine('hypervisor')
    __tablename__ = 'hypervisor'
    __table_args__ = {'autoload':True}
########################################################################
class iscsi(Base,mixin):
    """"""
    Base.metadata.bind = DBsession.getEngine('iscsi')
    __tablename__ = 'iscsi'
    __table_args__ = {'autoload':True}
########################################################################
class mic(Base,mixin):
    """"""
    Base.metadata.bind = DBsession.getEngine('mic')
    __tablename__ = 'mic'
    __table_args__ = {'autoload':True}
########################################################################
class ppcdirect(Base,mixin):
    """"""
    Base.metadata.bind = DBsession.getEngine('ppcdirect')
    __tablename__ = 'ppcdirect'
    __table_args__ = {'autoload':True}

    @classmethod
    def primkeys(cls):
        return tuple(['hcp'])
########################################################################
class storage(Base,mixin):
    """"""
    Base.metadata.bind = DBsession.getEngine('storage')
    __tablename__ = 'storage'
    __table_args__ = {'autoload':True}
########################################################################
class websrv(Base,mixin):
    """"""
    Base.metadata.bind = DBsession.getEngine('websrv')
    __tablename__ = 'websrv'
    __table_args__ = {'autoload':True}
########################################################################
class prescripts(Base,mixin):
    """"""
    Base.metadata.bind = DBsession.getEngine('prescripts')
    __tablename__ = 'prescripts'
    __table_args__ = {'autoload':True}
########################################################################
class ipmi(Base,mixin):
    """"""
    Base.metadata.bind = DBsession.getEngine('ipmi')
    __tablename__ = 'ipmi'
    __table_args__ = {'autoload':True}
########################################################################
class osimage(Base,mixin):
    """"""
    Base.metadata.bind = DBsession.getEngine('osimage')
    __tablename__ = 'osimage'
    __table_args__ = {'autoload':True}
########################################################################
class linuximage(Base,mixin):
    """"""
    Base.metadata.bind = DBsession.getEngine('linuximage')
    __tablename__ = 'linuximage'
    __table_args__ = {'autoload':True}
########################################################################
class winimage(Base,mixin):
    """"""
    Base.metadata.bind = DBsession.getEngine('winimage')
    __tablename__ = 'winimage'
    __table_args__ = {'autoload':True}
########################################################################
class nimimage(Base,mixin):
    """"""
    Base.metadata.bind = DBsession.getEngine('nimimage')
    __tablename__ = 'nimimage'
    __table_args__ = {'autoload':True}
########################################################################
class zone(Base,mixin):
    """"""
    Base.metadata.bind = DBsession.getEngine('zone')
    __tablename__ = 'zone'
    __table_args__ = {'autoload':True}
########################################################################
class osdistro(Base,mixin):
    """"""
    Base.metadata.bind = DBsession.getEngine('osdistro')
    __tablename__ = 'osdistro'
    __table_args__ = {'autoload':True}
########################################################################
class site(Base,mixin):
    """"""
    Base.metadata.bind = DBsession.getEngine('site')
    __tablename__ = 'site'
    __table_args__ = {'autoload':True}
########################################################################
    def getdict(self):
        mydict={}
        mykey=self.__dict__['key']
        mydict[self.__tablename__+'.'+mykey]=mykey=self.__dict__['value']
        return mydict

    @classmethod
    def dict2tabentry(self,objdict):
        mydict={}
        ret=[]
        for key in objdict.keys():
            mydict['key']=key
            mydict['value']=objdict[key]
            mydict['disable']=None
            ret.append(deepcopy(mydict))
        return ret
       
    @classmethod
    def getTabtype(self):
        return 'flat'
#----------------------------------------------------------------------

def query_table_by_node(session, tclass, tkey):
    """"""
    result=session.query(tclass).filter(tclass.node == tkey).all()
    if not result:
       return None 
    return result[0].getdict()


def query_nodelist_by_key(session, nodelist):
    """"""
    nodelist_value = {}
    for node in nodelist:
        nodelist_value[node]={}
        classlist = [Bootparams,Nodetype,Hosts,Switch,Mac,Noderes]
        for eachclass in classlist:
            clsdict = query_table_by_node(session,eachclass,node)
            nodelist_value[node].update(clsdict)
    return nodelist_value

if __name__ == "__main__":
     pass
  
