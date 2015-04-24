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

def authenticate(username,password):

    pagename = "Authentication %s"
    caption = "<i>Authentication %s</i>"
    msg_redir = '<small>You will be now redirected to <a href="%s">orignal site</a>.</small>'
    msg = '<p>... <small>authentication %s!</small></p>'

    try:
        bend = SOAPpy.SOAPProxy("http://localhost:65456/")
        success = bend.authenticate(ip,username,password,token)
     
        if success:
            r = None
            m = msg % ("succeeded",)
            
            # if success is positive, check if it's True, or some string
            if success != True:
                # string - this means it's redirection URL
                if success.startswith('http://') or success.startswith('https://'):
                    r = success
                else:
                    r = "http://" + success
                    
                m = msg_redir % r
                
            util.print_message(pagename % ("succeeded",), caption % ("succeeded",),m,redirect_url=r,redirect_time=0)
        else:
            util.print_message(pagename % ("failed",),caption % ("failed",),msg % ("failed",))
        
    except Exception,e:
        util.print_message("Whoops!","Exception caught!",str(e))

authenticate(username,password)



