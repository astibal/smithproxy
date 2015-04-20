import sys
import re
import fileinput
import pprint
import binascii

def list(fnm):
    for line in fileinput.input(files=[fnm,]):
        re_packet_start = re.compile(r'^\+\d+: +\d+::([^:]+):([^:]+)-\d+::([^:]+):([^:(]+)')

        sip = None
        dip = None
        sport = None
        dport = None
        have_connection = False


        if not have_connection:
            m = re_packet_start.search(line)
            if m:
                sip = m.group(1)
                dip = m.group(3)
                sport = m.group(2)
                dport = m.group(4)
                
                return "tcp",sip,sport,dip,dport
            
            
    return None

def convert_to_bytes(list_of_ords):
    bytes = ''

    for l in list_of_ords:
        for oord in l.split(" "):
            if oord:
                bytes += binascii.unhexlify(oord)

    return bytes


def read(fnm):

    server_port = 0

    packets = []
    origins = {}
    origins["client"] = []
    origins["server"] = []

    this_packet_origin = None
    this_packet_index = 0
    this_packet_bytes = []

    have_connection = False

    for line in fileinput.input(files=[fnm,]):

        re_packet_start = re.compile(r'^\+\d+: +\d+::([^:]+):([^:]+)-\d+::([^:]+):([^:(]+)')
        re_packet_content_client = re.compile(r'^>\[([0-9a-f])+\][^0-9A-F]+([0-9A-F ]{2,49})')
        re_packet_content_server = re.compile(r'^ +<\[([0-9a-f])+\][^0-9A-F]+([0-9A-F ]{2,49})')

        sip = None
        dip = None
        sport = None
        dport = None

        if not have_connection:
            m = re_packet_start.search(line)
            if m:
                sip = m.group(1)
                dip = m.group(3)
                sport = m.group(2)
                dport = m.group(4)
                have_connection = True

                server_port = dport


        matched = False
        m = None

        if not matched:
            m = re_packet_content_client.search(line)
            if m:
                #print_green_bright(line.strip())
                #print_green(m.group(2))
                this_packet_bytes.append(m.group(2))
                this_packet_origin = 'client'
                matched = True

        if not matched:
            m = re_packet_content_server.search(line)
            if m:
                #print_red(m.group(2))
                this_packet_bytes.append(m.group(2))
                this_packet_origin = 'server'
                matched = True

        if not matched:
            if this_packet_bytes:
                #finalize packet


                data = convert_to_bytes(this_packet_bytes)
                if this_packet_origin == 'client':
                    #print_green("# Converted: -->\n%s\n#<--" % (data,))
                    packets.append(data)
                    origins['client'].append(this_packet_index)
                else:
                    #print_red("# Converted: -->\n%s\n#<--" % (data,))
                    packets.append(data)
                    origins['server'].append(this_packet_index)

                this_packet_bytes = []
                this_packet_origin = None
                this_packet_index += 1

    return packets, origins

def pythonize(packets,origins,global_comment="",init_comment="",nice_crlf=True):

    c = "# " + global_comment + "\n\n"
    c += "class SmcapData:\n\n"
    c += "    def __init__(self):\n"
    c += "        # let's init this: " + init_comment + "\n"
    c += "        self.packets = []\n"
    
    i = 0
    for p in packets:
        side = "SERVER"
        index = -1
        if i in origins['client']:
            side = "CLIENT"
            index = origins['client'].index(i)
        else:
            index = origins['server'].index(i)
            
        c += "        # %d: %s:%d size=%dB\n" % (i,side,index,len(p))
        
        if nice_crlf:
            sep_p = p.split('\r\n')
            if len(sep_p) > 1:
                c += "        _lines=[]\n"
                for s in sep_p:
                    c += "        _lines.append(%s)\n" % repr(str(s),)
                
                c += "        self.packets.append(\"\\r\\n\".join(_lines))\n\n"
                
            else:
                c += "        self.packets.append(%s)\n\n" % repr(str(p),)
        else:
            c += "        self.packets.append(%s)\n\n" % repr(str(p),)
        i += 1

    c += "        self.origins = {}\n\n"
    for k in origins.keys():
        c+= "        self.origins['%s']=%s\n" % (k,origins[k])

    c+="\n\n"
    c+="""
    """

    return c

def pythonize_file(fnm):
    p,o = read(fnm)
    return pythonize(p,o,global_comment="exported from %s" % (fnm,) )

def export(fnm,efile):
    c = pythonize_file(fnm)
    
    if not c:
        return 0
    
    if not efile or efile == "-":
        print c
        return len(c)
    else:
        f = open(efile,'w')
        f.write(c)
        f.close()
        


#export(sys.argv[1],sys.argv[2])
