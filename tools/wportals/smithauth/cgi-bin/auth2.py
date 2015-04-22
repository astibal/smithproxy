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
import SOAPpy

# Create instance of FieldStorage 
form = cgi.FieldStorage() 

# Get data from fields
username = form.getvalue('username')
password = form.getvalue('password')
token = None
if "token" in form.keys():
  token = form["token"].value

def authenticate(username,password):

    pagename_ok = "Authentication succeeded"
    caption_ok = "<i>Authentication succeeded</i>"
    msg_ok = 'You will be now redirected to orignal site.'

    pagename_authfailed = "Authentication failed"
    caption_authfailed = "<i>Authentication failed... </i>"
    msg_authfailed = 'Authentication failed. '

    try:
	bend = SOAPpy.SOAPProxy("http://localhost:65456/")
        success = bend.authenticate(username,password,token)
     
        if success:
	    util.print_message(pagename_ok, caption_ok,msg_ok,redirect_url="http://"+success,redirect_time=0)
	else:
	    util.print_message(pagename_authfailed,caption_authfailed,msg_authfailed)
	    
    except Exception,e:
	util.print_message("Whoops!","Exception caught!",str(e))

authenticate(username,password)



