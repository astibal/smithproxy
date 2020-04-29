import logging
import pprint
import sys

import auth.ldapcon
import pylibconfig2 as cfg


def load_config(fnm):
    try:
        conf = cfg.Config()
        conf.read_file(fnm)
        return conf

    except Exception as e:
        print("Error loading file: " + str(e))

    return None


def cfg_2_dict(cfg_element):
    # this is materialization of the shame of pylibconfig2. 
    # It cannot convert ConfigGroup into dictionary. Poor.
    if isinstance(cfg_element, cfg.ConfGroup):
        d = {}
        for c in cfg_element.items():
            k = c[0]
            v = c[1]
            if isinstance(v, cfg.ConfGroup) or isinstance(v, cfg.ConfList):
                v = cfg_2_dict(v)
            d[k] = v
    elif isinstance(cfg_element, cfg.ConfList):
        d = []
        for l in cfg_element:
            d.append(cfg_2_dict(l))
    elif isinstance(cfg_element, tuple):
        d = {}
        if isinstance(cfg_element[1], cfg.ConfGroup) or isinstance(cfg_element[1], cfg.ConfList):
            d[cfg_element[0]] = cfg_2_dict(cfg_element[1])
        else:
            d[cfg_element[0]] = cfg_element[1]
    else:
        return cfg_element

    return d


class AAAResolver:
    def __init__(self):
        self.profiles = {}  # name->profile ... profile is 

    def create_profile(self, cfg_element):  # cfg.ConfGroup

        _ = cfg_element[0]
        values = cfg_element[1]

        if "ip" not in values.keys() \
                or "bind_dn" not in values.keys() \
                or "bind_pw" not in values.keys() \
                or "base_dn" not in values.keys():

            print("Config is missing mandatory entries!")
            return None
        else:
            print("OK")


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s [%(process)d] [%(levelname)s] %(message)s')
    config_file = "/etc/smithproxy/users.cfg"

    confed = load_config(config_file)
    confed = cfg_2_dict(confed)

    l = auth.ldapcon.LdapSearch()
    l.updateProfile(confed["sources"]["ldap"]["example_ldap"])
    pprint.pprint(l.profile)
    print("-------")
    l.init()
    l.bind()

    if len(sys.argv) > 2:
        pprint.pprint(l.authenticate_user(sys.argv[1], sys.argv[2]))
    else:
        pprint.pprint(l.authenticate_user("admin", "smithproxy"))
