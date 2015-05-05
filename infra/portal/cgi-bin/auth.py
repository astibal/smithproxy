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


import SOAPpy
import time
import cgi, cgitb 
import util
import os

#	removed head:
# 	<link rel=stylesheet type="text/css" href="/css/styles.css">	
#	<script type="text/javascript" src="/js/keyboard.js" charset="UTF-8"></script>
# 	<link rel="stylesheet" type="text/css" href="/css/keyboard.css">
form = cgi.FieldStorage() 

ref = os.environ["HTTP_REFERER"]

token = None
if "token" in form.keys():
  token = form["token"].value

page = """
<html>
<head>
	<title>Authentication required</title>
	<META HTTP-EQUIV="Content-Type" CONTENT="text/html; charset=utf-8">
	<script type="text/javascript">
	</script>
</head>
<body>
<form action="/cgi-bin/auth2.py?a=z%s" method="post">
<div>
  <table align="center">
    <tr><th colspan="2">Authentication required:</th><tr>
    <tr><td colspan="2"></td></tr>
    <tr><td>Username:</td><td><input type="text" name="username"</td></tr>
    <tr><td>Password:</td><td><input type="password" name="password"></td></tr>
    <tr><td>         </td><td><input type="submit" name="ok" value="OK"></td></tr>
    <tr><td colspan="2"></td></tr>
  </table>
</div>
</form>
</body>
</html>"""

# use class="keyboardInput" for virtual keyboard below the input field

try:
	if token:
	  tok_str = "&token="+str(token)
	  print page % (tok_str,)
	else:
	  print page % ('',)
	  
        bend = SOAPpy.SOAPProxy("http://localhost:65456/")
        
        if ref:
	    bend.save_referer(token,ref)

except Exception, e:
	util.print_message("Error","Error occured:", str(e),"/error.html")

