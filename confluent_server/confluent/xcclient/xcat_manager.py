###############################################################################
# IBM(c) 2019 EPL license http://www.eclipse.org/legal/epl-v10.html
###############################################################################

# -*- coding: utf-8 -*-

import os
import confluent.log as log
from .dbsession import DBsession
from .dbfactory import dbfactory
xcat_dbi=None

class xCATConfigManager(object):
    def __init__(self):
        global xcat_dbi
        if xcat_dbi is None:
            dbsession = DBsession()
            xcat_dbi = dbfactory(dbsession)
        self.logger = log.Logger("xcat_manager") 
        self.logger.log("Init xCAT configManager")

    def list_nodes(self):
        try:
            dataset = xcat_dbi.gettab(['nodelist', 'nodegroup'])
            self.logger.log("list_nodes %s" % (dataset.keys()))
            return iter(dataset.keys())
        except KeyError:
            return [] 
    def log(self, logmsg):
        self.logger.log(logmsg)
