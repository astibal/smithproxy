
import sys
import pprint


import pylibconfig2 as cfg
import ldapcon

def load_config(fnm):
    try:
        c = cfg.Config()
        c.read_file(fnm)
        return c
    
    except Exception, e:
        print "Error loading file: " + str(e)
        
    return None

def cfg_2_dict(cfg_element):
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

class AAAResolver:
    def __init__(self):
        self.profiles = {}  # name->profile ... profile is 
    
    def create_profile(self,cfg_element):  #cfg.ConfGroup
        key = cfg_element[0]
        values = cfg_element[1]
        
        #print str(values)
        #for s in values.items():
        #    print str(s)
    
        if "ip" not in values.keys() \
            or "bind_dn" not in values.keys() \
            or "bind_pw" not in values.keys() \
            or "base_dn" not in values.keys():
            print "Config is missing mandatory entries!"
            return None
        else:
            print "OK" 
            
        
            
        

if __name__ == "__main__":
    c = "smithproxy.cfg"
    c = load_config(c)
    c = cfg_2_dict(c)
    a = AAAResolver()
    
    
    for server in c.auth_servers.items():
        #pprint.pprint(server)
        #pprint.pprint(cfg_2_dict(server))
        a.create_profile(server)
        
        
        
    
