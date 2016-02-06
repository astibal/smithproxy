"""
    Smithproxy- transparent proxy with SSL inspection capabilities.
    Copyright (c) 2014, Ales Stibal <astib@mag0.net>, All rights reserved.

    Smithproxy is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Smithproxy is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Smithproxy.  If not, see <http://www.gnu.org/licenses/>.  """

import logging
import pylibconfig2 as cfg

def cfgloglevel_to_py(cfglevel):
    if(cfglevel >= 7):
        return logging.DEBUG
    elif(cfglevel >= 5):
        return logging.INFO
    elif(cfglevel == 4):
        return logging.WARNING
    elif(cfglevel == 3):
        return logging.ERROR
    else:
        return logging.FATAL
    

def cfg_to_dict(cfg_element):
    # this is materialization of the shame of pylibconfig2. 
    # It cannot convert ConfigGroup into dictionary. Poor.
    if isinstance(cfg_element,cfg.ConfGroup):
        d = {}
        for c in cfg_element.items():
            k = c[0]
            v = c[1]
            if isinstance(v,cfg.ConfGroup) or isinstance(v,cfg.ConfList):
                v = cfg_2_dict(v)
            d[k] = v
    elif isinstance(cfg_element,cfg.ConfList):
        d = []
        for l in cfg_element:
            d.append(cfg_2_dict(l))
    elif isinstance(cfg_element,tuple):
        d = {}
        if isinstance(cfg_element[1],cfg.ConfGroup) or isinstance(cfg_element[1],cfg.ConfList):
            d[cfg_element[0]] = cfg_2_dict(cfg_element[1])
        else:
            d[cfg_element[0]] = cfg_element[1]
    else:
        return cfg_element

    
    return d

def intersect_lists(l1,l2):
    return [filter(lambda x: x in l1, sublist) for sublist in l2]


def unique_list(l):
    ret = []
    for ll in l:
        if ll not in ret:
            ret.append(ll)
            
    return ret

def unique_prefixes(lst,delim):
    u = []
    
    for l in lst:
        if l.find(delim) >= 0:
            prefix = l.split(delim)
            if prefix not in u:
                u.append(prefix)
    return u