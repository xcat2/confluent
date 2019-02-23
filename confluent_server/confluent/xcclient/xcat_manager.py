#!/usr/bin/env python
###############################################################################
# IBM(c) 2019 EPL license http://www.eclipse.org/legal/epl-v10.html
###############################################################################

# -*- coding: utf-8 -*-

import os
import confluent.log as log
from functools import wraps
from .dbsession import DBsession
from .dbfactory import dbfactory
from .attributes import conattr2xcatattr
xcat_dbi=None
data_store=None
xcfm_logger=None
def xcat_manager_decorator(function):
    @wraps(function)
    def decorator(*args, **kwargs):
        xcfm_logger.log("In xCAT configManager: run " + function.__name__)
        return function(*args, **kwargs)
    return decorator

class xCATConfigManager(object):
    global data_store
    data_store={}
    data_store['nodes']={}
    data_store['nodegroup']=[]

    def __init__(self):
        global xcat_dbi
        if xcat_dbi is None:
            dbsession = DBsession()
            xcat_dbi = dbfactory(dbsession)
        global xcfm_logger
        if xcfm_logger is None:
            xcfm_logger = log.Logger("xcat_manager")
        xcfm_logger.log("Init xCAT configManager")
        self.decrypt = False
        self.current_user = 'xcat'
        self.tenant = None
        self._list_nodes()
        self._list_nodegroup() 
    def _get_data_from_db(self):
        try:
            nodelist_set = xcat_dbi.gettab(['nodelist'])
            nodelist = nodelist_set.keys()
        except KeyError:
            data_store['nodes'] = {}
            return
        attrs_dict = conattr2xcatattr('*')
        xcat_dbs=attrs_dict.values() 
        db_hash = {}
        for e in xcat_dbs:
            if e is None:
                continue
            elif isinstance(e, list):
                continue
            else:
                t,p,c=e.rpartition('.')
                if t in db_hash:
                    db_hash[t].append(c)
                else:
                    db_hash[t]=[c]
        dataset = xcat_dbi.gettab(db_hash.keys())
        for node in nodelist:
            nodeinfo = {} 
            for attr in attrs_dict.keys():
                self.log("The attr:" + attr)
                nodeinfo[attr] = {}
                if attrs_dict[attr] is None:
                    nodeinfo[attr]['value'] = None
                elif isinstance(attrs_dict[attr], list):
                    nodeinfo[attr]['value'] = attrs_dict[attr]
                elif attrs_dict[attr] in dataset[node]:
                    nodeinfo[attr]['value'] = dataset[node][attrs_dict[attr]]
                else:
                    nodeinfo[attr]['value'] = attrs_dict[attr]
            data_store['nodes'][node] = nodeinfo
        
    def _list_nodes(self):
        self._get_data_from_db()

    def _list_nodegroup(self):
        try:
            dataset = xcat_dbi.gettab(['nodegroup'])
            data_store['nodegroup'] = dataset.keys() 
        except KeyError:
            data_store['nodegroup'] = []
    @xcat_manager_decorator
    def list_nodes(self):
        try:
            dataset = xcat_dbi.gettab(['nodelist', 'nodegroup'])
            return iter(dataset.keys())
        except KeyError:
            return []
    @xcat_manager_decorator
    def get_groups(self, sizesort=False):
        if len(data_store['nodegroup']) == 0:
            self._list_nodegroup()
        return data_store['nodegroup']
    @xcat_manager_decorator
    def is_node(self, node):
        return node in data_store['nodes'].keys()

    @xcat_manager_decorator
    def is_nodegroup(self, nodegroup):
        return nodegroup in data_store['nodegroup']

    @xcat_manager_decorator
    def check_quorum(self):
        pass
    @xcat_manager_decorator
    def get_node_attributes(self, nodelist, attributes=(), decrypt=None):
        ret_dict = {}
        if '*' in nodelist:
            nodelist = data_store['nodes'].keys()
        if len(nodelist) == 0:
            return None
        if len(set(nodelist) - set(data_store['nodes'].keys())):
            self._get_data_from_db()
        if '*' in attributes or attributes == ():
            for node in nodelist:
                ret_dict[node] = data_store['nodes'][node]
            self.log(self.__class__.__name__ + "==> get all attributes for: " + str(nodelist))
            self.log(str(ret_dict))
            return ret_dict
        self.log(self.__class__.__name__ + "==> get attributes:" + str(attributes) + "for: " + str(nodelist))
        for node in nodelist:
            nodeinfo = {}
            for attr in attributes:
                nodeinfo[attr] = data_store['nodes'][node][attr]
            ret_dict[node] = nodeinfo
        return ret_dict
    @xcat_manager_decorator
    def get_collective_member(self, name):
        return None
        #return get_collective_member(name)
    @xcat_manager_decorator
    def watch_attributes(self, nodes, attributes, callback): 
        pass

    def log(self, logmsg):
        xcfm_logger.log(logmsg)
if __name__ == '__main__':
    xcfm = xCATConfigManager()
    xcfm.get_node_attributes()
