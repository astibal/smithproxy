#!/usr/bin/python3

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
    


# Import modules for CGI handling 
import cgi, cgitb 
import util
import os
from zeep import Client as SoapClient
import traceback
import logging

print_exceptions = True

tenant_name = "default"
if "TENANT_NAME" in os.environ.keys():
    tenant_name = os.environ["TENANT_NAME"]

tenant_index = 0
if "TENANT_IDX" in os.environ.keys():
    tenant_index = int(os.environ["TENANT_IDX"])


bend_url = "http://127.0.0.1:%d/?wsdl" % (64000 + tenant_index)

def create_logger(name):
    ret = logging.getLogger(name)
    hdlr = logging.FileHandler("/tmp/smithproxy_%s.log" % (name,))
    formatter = logging.Formatter('%(asctime)s [%(process)d] [%(levelname)s] %(message)s')
    hdlr.setFormatter(formatter)
    ret.addHandler(hdlr) 
    ret.setLevel(logging.INFO)
    
    return ret

flog = create_logger("portal_auth2_%s" % (tenant_name,))

def authenticate(username,password,token):
    global print_exceptions,bend_url

    

    pagename = "Authentication %s"
    caption = "Authentication %s"
    msg = 'authentication %s!'

    try:
        if username:
            bend = bend = SoapClient(bend_url)
            success, ref = bend.service.authenticate(ip, username, password, token)
        
        
            xref = ref
            if token == "0":
                xref = "/cgi-bin/auth.py?a=z&token=0"
        
            if success == "1":
                flog.info("User %s authentication successful from %s" % (username,ip))
                xmsg = msg % ("successful! You will be now redirected to originally requested site",)
                if token == 0:
                    xmsg = msg % ("successful! You will be redirected to your status page",)
                
                util.print_message(pagename % ("succeeded",), 
                                    caption % ("succeeded",),
                                    xmsg,
                                    redirect_url=xref,
                                    redirect_time=0)
                    
            else:
                flog.info("User %s authentication failed from %s" % (username,ip))
                util.print_message(pagename % ("failed",),
                                caption % ("failed",),
                                msg % ("failed",),
                                redirect_url=xref,
                                redirect_time=1)
        else:
            util.print_message(" ",
                            " ",
                            "...",
                            redirect_url="/cgi-bin/auth.py?token=%s" % (token,),
                            redirect_time=0)

        
    except Exception as e:
        flog.error("exception caught: %s" % (str(e),))
        if print_exceptions:
            util.print_message("Whoops!","Exception caught!",str(e) +" " + traceback.format_exc(100)) + " backend URL %s" % (bend_url,)
        else:
            util.print_message(u"Authentication failed",
                               u"Authentication failed",
                               u"There was a problem to validate your credentials. Please contact system administrator.")


# Create instance of FieldStorage 
form = cgi.FieldStorage() 

# Get data from fields
username = form.getvalue('username')
password = form.getvalue('password')
token = "0"
if "token" in form.keys():
  token = form["token"].value

ip = os.environ["REMOTE_ADDR"]
if(ip.startswith("::ffff:")):
    ip = ip[7:]
ref= os.environ["HTTP_REFERER"]

authenticate(username,password,token)

