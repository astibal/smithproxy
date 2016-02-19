#!/usr/bin/python

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
    


# Import modules for CGI handling 
import cgi, cgitb 
import util
import os
import SOAPpy
import traceback

print_exceptions = True

tenant_name = "default"
if "TENANT_NAME" in os.environ.keys():
    tenant_name = os.environ["TENANT_NAME"]

tenant_index = 0
if "TENANT_IDX" in os.environ.keys():
    tenant_index = int(os.environ["TENANT_IDX"])


bend_url = "http://127.0.0.1:%d/" % (tenant_index+64000,)

def authenticate(username,password,token):
    global print_exceptions,bend_url

    pagename = "Authentication %s"
    caption = "Authentication %s"
    msg = 'authentication %s!'

    try:
        if username:
            bend = SOAPpy.SOAPProxy(bend_url)
            success,ref = bend.authenticate(ip,username,password,token)
        
        
            xref = ref
            if token == "0":
                xref = "/cgi-bin/auth.py?a=z&token=0"
        
            if success:
                xmsg = msg % ("successful! You will be now redirected to originally requested site",)
                if token == 0:
                    xmsg = msg % ("successful! You will be redirected to your status page",)
                
                util.print_message(pagename % ("succeeded",), 
                                    caption % ("succeeded",),
                                    xmsg,
                                    redirect_url=xref,
                                    redirect_time=0)
                    
            else:
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

        
    except Exception,e:
        if print_exceptions:
            util.print_message("Whoops!","Exception caught!",str(e) +" " + traceback.format_exc(100)) + " backend URL %s" % (bend_url,)
        else:
            util.print_message("Authentication failed","Authentication failed","There was a problem to validate your credentials. Please contact system administrator.")


# Create instance of FieldStorage 
form = cgi.FieldStorage() 

# Get data from fields
username = form.getvalue('username')
password = form.getvalue('password')
token = "0"
if "token" in form.keys():
  token = form["token"].value

ip = os.environ["REMOTE_ADDR"]
ref= os.environ["HTTP_REFERER"]

authenticate(username,password,token)

