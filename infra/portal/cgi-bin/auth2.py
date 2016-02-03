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

# Create instance of FieldStorage 
form = cgi.FieldStorage() 

# Get data from fields
username = form.getvalue('username')
password = form.getvalue('password')
token = None
if "token" in form.keys():
  token = form["token"].value

ip = os.environ["REMOTE_ADDR"]
ref= os.environ["HTTP_REFERER"]

def authenticate(username,password):

    pagename = "Authentication %s"
    caption = "<i>Authentication %s</i>"
    msg_redir = '<small>You will be now redirected to <a href="%s">orignal site</a>.</small>'
    msg = '<p>... <small>authentication %s!</small></p>'

    try:
        bend = SOAPpy.SOAPProxy("http://localhost:65456/")
        success,ref = bend.authenticate(ip,username,password,token)
     
        if success:
            util.print_message(pagename % ("succeeded",), 
                                caption % ("succeeded",),
                                msg % ("was successful! You will be now redirected to originally requested site",),
                                redirect_url=ref,
                                redirect_time=0)
        else:
            util.print_message(pagename % ("failed",),
                               caption % ("failed",),
                               msg % ("was not successful!",),
                               redirect_url=ref,
                               redirect_time=1)
        
    except Exception,e:
        util.print_message("Whoops!","Exception caught!",str(e))

authenticate(username,password)



