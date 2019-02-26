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
    along with Smithproxy.  If not, see <http://www.gnu.org/licenses/>.

    Linking Smithproxy statically or dynamically with other modules is
    making a combined work based on Smithproxy. Thus, the terms and
    conditions of the GNU General Public License cover the whole combination.

    In addition, as a special exception, the copyright holders of Smithproxy
    give you permission to combine Smithproxy with free software programs
    or libraries that are released under the GNU LGPL and with code
    included in the standard release of OpenSSL under the OpenSSL's license
    (or modified versions of such code, with unchanged license).
    You may copy and distribute such a system following the terms
    of the GNU GPL for Smithproxy and the licenses of the other code
    concerned, provided that you include the source code of that other code
    when and as the GNU GPL requires distribution of source code.

    Note that people who make modified versions of Smithproxy are not
    obligated to grant this special exception for their modified versions;
    it is their choice whether to do so. The GNU General Public License
    gives permission to release a modified version without this exception;
    this exception also makes it possible to release a modified version
    which carries forward this exception.
    """
from __future__ import print_function

import logging

def cfgloglevel_to_py(cfglevel):

    if cfglevel >= 7:
        return logging.DEBUG

    elif cfglevel >= 5:
        return logging.INFO

    elif cfglevel == 4:
        return logging.WARNING

    elif cfglevel == 3:
        return logging.ERROR

    else:
        return logging.FATAL
    

def cfg_to_dict(cfg_element):

    import pylibconfig2 as cfg

    # this is materialization of the shame of pylibconfig2. 
    # It cannot convert ConfigGroup into dictionary. Poor.
    if isinstance(cfg_element,cfg.ConfGroup):
        d = {}
        for c in cfg_element.items():
            k = c[0]
            v = c[1]
            if isinstance(v,cfg.ConfGroup) or isinstance(v,cfg.ConfList):
                v = cfg_to_dict(v)
            d[k] = v
    elif isinstance(cfg_element,cfg.ConfList):
        d = []
        for l in cfg_element:
            d.append(cfg_to_dict(l))
    elif isinstance(cfg_element,tuple):
        d = {}
        if isinstance(cfg_element[1],cfg.ConfGroup) or isinstance(cfg_element[1],cfg.ConfList):
            d[cfg_element[0]] = cfg_to_dict(cfg_element[1])
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


#
# Ask question, until you get answer from the list.
# Default is the first choice, choices are case insensitive.
# If choices start with same letters, shortcut response is ambiguous and first in the choice list will be returned.
# So you want avoid ambiguous choices ;-)
#
def ask_bot(answers, question):


    norm_answers = []
    for a in answers:
        norm_answers.append(a.strip().lower())

    trailer = '['
    for a in answers:
        trailer += a
        trailer += '/'

    # remove last /
    trailer = trailer[:-1]
    trailer += ']'

    ask_question = question + " " + trailer + "? "

    ret = None
    while True:
        response = input(ask_question)
        rr = response.strip().lower()

        # print("response: '" + rr + "'")

        i = 0
        for a in norm_answers:
            # print(a + "?" + rr)

            if a.startswith(rr):
                ret = answers[i]

                # print("ret="+a)
                break
            i += 1

        if ret:
            # print("ret="+a)
            break
    return ret



