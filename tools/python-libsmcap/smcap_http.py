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

import sys
import re
import zlib
import fileinput
import pprint
import binascii

def detect_http(gen):
    try:
        if(gen['have_lines']):
            # locate index of first client request
            i  = gen['origins']['client'][0]
            
            # locate index of first server response
            j  = gen['origins']['server'][0]
            
            if gen['lines'][i][0].startswith('GET') or gen['lines'][i][0].startswith('POST'):
                if gen['lines'][j][0].startswith('HTTP'):
                    return True
            
    except KeyError, e:
        return False
    except IndexError, e:
        return False
    
    return False
    
def process_http(gen):
    c = ''
    try:
        if(gen['have_lines']):
            # locate index of first client request
            i  = gen['origins']['client'][0]
            
            # locate index of first server response
            j  = gen['origins']['server'][0]

            # traverse all clients
            for client_request in gen['origins']['client']:
                print "process_http: client " + str(client_request)
                c += process_http_request(gen, client_request)
            
            for client_request in gen['origins']['server']:
                print "process_http: server" + str(client_request)
                c += process_http_response(gen, client_request)

            
            
    except KeyError, e:
        return " "*8 + "# Exception caught: " + str(e) + "\n" +" "*8 + "# Partial output:\n" + c
    except IndexError, e:
        return " "*8 + "# Exception caught: " + str(e) + "\n" +" "*8 + "# Partial output:\n" + c
    
    return c


def process_http_request(gen, request_origin_index):
    
    c = ''
    concat_data = http_concat_by_origin(gen,'client',request_origin_index)
    
    print "# --- request:"
    for l in concat_data[:5]:
        print l
        pass

    request_str = ''
    
    r = in_list_re_search(concat_data, "Host: ([^ ]+)")
    if r:
        request_str += r.group(1)
        
    r = in_list_re_search(concat_data, "(GET|POST|HEAD) +([^ ]+)")
    if r:
        request_str += r.group(2)

    c += " "*8 + "self.http['request'] = %s\n" % (repr(str(request_str)),)
    gen['http']['request'] = request_str

    c += " "*8 + "# http client request processed.\n\n"
    
    return c

def in_list_re_search(li, what):
    for l in li:
        r = re.search(what,l)
        if r:
            return r
        
    return None
        


def process_http_response(gen, request_origin_index):
    
    c = ''
    concat_data = http_concat_by_origin(gen,'server',request_origin_index)
    
    print "# --- response:"
    for l in concat_data[:5]:
        print l
        pass


    body_index = 0
    body_mass = ''
    try:
        # empty line is start of the data
        body_index = concat_data.index('')
        body_mass = concat_data[body_index+1:-1]

       
        print "# --- response body:"
        print str(body_mass)
    except ValueError, e:
        pass
        

    # Chunked content check
    r = in_list_re_search(concat_data,'Transfer-Encoding: *chunked')
    if r:
        c += " "*8 + "# chunked data encoding detected: glued together\n"
        merged_chunks = merge_chunked_data(body_mass)
        
        #c+= " "*8 + "self.http['response'] = %s\n" % (repr(str(merged_chunks)),)
        body_mass = merged_chunks


    r = in_list_re_search(concat_data,'Content-Encoding: *deflate')
    if r:
        c += " "*8 + "# compressed data detected: decompressed\n"
        body_mass = zlib.decompress(body_mass)

        
    c+= " "*8 + "self.http['response'] = %s\n" % (repr(str(body_mass)),)
    

    c += " "*8 + "# http server response processed.\n"
    return c


def merge_chunked_data(d):
    ret = ''
    i = 0
    for dd in d:
        if i % 2 == 1:
            ret += dd
        i=i+1

    return ret

def http_concat_by_origin(gen, role, index):
    
    data_to_concat = []
    cur_index = index
    
    peer_role = 'client'
    
    if role == "client":
        peer_role = 'server'
    
    while True:
        print "processing origin index " + str(cur_index)
        
        cur_lines = gen['lines'][cur_index]
        data_to_concat += cur_lines
        
        #print "merged lines so far:\n" + str(data_to_concat) + "\n"
        
        if cur_index + 2 >= len(gen['lines']):
            print "next index is already out of bounds"
            break
        else:
            if (cur_index + 1) not in gen['origins'][peer_role]:
                print "next index is ours. continue."
                cur_index = cur_index + 1
            else:
                print "next index is NOT ours. done."  
                break
        
    return data_to_concat
