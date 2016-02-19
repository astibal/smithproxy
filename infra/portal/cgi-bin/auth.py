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
import logging

#	removed head:
# 	<link rel=stylesheet type="text/css" href="/css/styles.css">	
#	<script type="text/javascript" src="/js/keyboard.js" charset="UTF-8"></script>
# 	<link rel="stylesheet" type="text/css" href="/css/keyboard.css">
form = cgi.FieldStorage() 

ip = "unknown"
if "REMOTE_ADDR" in os.environ.keys():
    ip = os.environ["REMOTE_ADDR"]

ref = "unknown"    
if "HTTP_REFERER" in os.environ.keys():
    ref = os.environ["HTTP_REFERER"]

port = "unknown"
if "SERVER_PORT" in os.environ.keys():
    port = os.environ["SERVER_PORT"]

tenant_name = "default"
if "TENANT_NAME" in os.environ.keys():
    tenant_name = os.environ["TENANT_NAME"]

tenant_index = 0
if "TENANT_IDX" in os.environ.keys():
    tenant_index = int(os.environ["TENANT_IDX"])


token = "0"
if "token" in form.keys():
  token = form["token"].value

logoff = "0";
if "logoff" in form.keys():
  logoff = form["logoff"].value
  
style = """
    <style media="screen" type="text/css">
        * {
        box-sizing: border-box;
        }
        
        *:focus {
        outline: none;
        }
        body {
        font-family: Arial;
        background-color: #48617B;
        padding: 50px;
        }
        .login {
        margin: 20px auto;
        width: 300px;
        }
        .login-screen {
        background-color: #FFF;
        padding: 20px;
        border-radius: 5px
        }
        
        .app-title {
        text-align: center;
        color: #777;
        }
        
        .login-form {
        text-align: center;
        }
        .control-group {
        margin-bottom: 10px;
        }
        
        input {
        text-align: center;
        background-color: #ECF0F1;
        border: 2px solid transparent;
        border-radius: 3px;
        font-size: 16px;
        font-weight: 200;
        padding: 5px 0;
        width: 250px;
        transition: border .5s;
        }
        
        input:focus {
        border: 2px solid #3498DB;
        box-shadow: none;
        }
        
        .btn {
        border: 2px solid transparent;
        background: #3498DB;
        color: #ffffff;
        font-size: 16px;
        line-height: 25px;
        padding: 5px 0;
        text-decoration: none;
        text-shadow: none;
        border-radius: 3px;
        box-shadow: none;
        transition: 0.25s;
        display: block;
        width: 250px;
        margin: 0 auto;
        }
        
        .btn:hover {
        background-color: #2980B9;
        }
        
        .login-link {
        font-size: 12px;
        color: #444;
        display: block;
        margin-top: 12px;
        }
    </style>
"""

auth_page = """
<html>
<head>
	<title>Authentication required</title>
	<META HTTP-EQUIV="Content-Type" CONTENT="text/html; charset=utf-8">
	<script type="text/javascript">
	</script>
    %s
</head>
<body>

<form action="/cgi-bin/auth2.py?a=z%s" method="POST">
 <div class="login">
 <div class="login-screen">
 <div class="app-title">
 <!-- port %s -->
 <h2>Authentication required:</h2>
 </div>
 
 <div class="login-form">
 <div class="control-group">
 <input type="text" class="login-field" value="" placeholder="username" name="username">
 <label class="login-field-icon fui-user" for="login-name"></label>
 </div>
 
 <div class="control-group">
 <input type="password" class="login-field" value="" placeholder="password" name="password">
 <label class="login-field-icon fui-lock" for="login-pass"></label>
 </div>
 
  <input type="submit" value="Log in" class="btn btn-primary btn-large btn-block" >
  <br>
 </div>
 </div>
 </div>
</form>

</body>
</html>"""


logged_page = """
<html>
<head>
    <title>Already logged in</title>
    <META HTTP-EQUIV="Content-Type" CONTENT="text/html; charset=utf-8">
    <meta http-equiv="refresh" content="10">
    <script type="text/javascript">
    </script>
    %s
</head>
<body>
        <form action="/cgi-bin/auth.py?a=z&logoff=1" method="POST">
        <div class="login">
        <div class="login-screen">
        <div class="app-title">
        <h2>Logged in</h2>
            as '<strong>%s</strong>'
            </br>
            <small>...</small>
        </div>

        <input type="submit" value="Login as different user" class="btn btn-primary btn-large btn-block" ></br>
        </div>
        </div>
        </div>        
        </form>
</body>
"""

# use class="keyboardInput" for virtual keyboard below the input field

bend_url = "http://127.0.0.1:%d/" % (64000+tenant_index)

try:
    if ref:
        bend = SOAPpy.SOAPProxy(bend_url)
        bend.save_referer(token,ref)
        
    if token != "0":
        tok_str = "&token="+str(token)
        print   auth_page % (style,tok_str,str(port)+"-"+tenant_name+"-"+str(tenant_index))
    else:
        if ip:
            bend = SOAPpy.SOAPProxy(bend_url)
            logon_info = bend.whois(ip)
            
            if logon_info != []:
                if logoff == "0":
                    print logged_page % (style,logon_info[1])
                else:
                    bend.deauthenticate(ip)
                    print auth_page % (style,"0",str(port)+"-"+tenant_name+"-"+str(tenant_index))
                    
            else:
                print   auth_page % (style,"0",str(port)+"-"+tenant_name+"-"+str(tenant_index))
                

except Exception, e:
    util.print_message("Error","Error occured:", str(e),"/error.html")
    logging.error("auth.py: exception caught: " + str(e))

