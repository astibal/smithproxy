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


import SOAPpy
import time
import cgi, cgitb 
import util
import os
import logging


def create_logger(name):
    ret = logging.getLogger(name)
    hdlr = logging.FileHandler("/var/log/smithproxy_%s.log" % (name,))
    formatter = logging.Formatter('%(asctime)s [%(process)d] [%(levelname)s] %(message)s')
    hdlr.setFormatter(formatter)
    ret.addHandler(hdlr) 
    ret.setLevel(logging.INFO)
    
    return ret

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


flog = create_logger("portal_auth1_%s" % (tenant_name,))

token = "0"
if "token" in form.keys():
  token = form["token"].value

logoff = "0";
if "logoff" in form.keys():
  logoff = form["logoff"].value
  
status = 0;
if "status" in form.keys():
  status = form["status"].value



style_small = """
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
        padding: 20px;
        }
        .login {
        margin: 10px auto;
        width: 200px;
        }        
        
        .login-screen {
        background-color: #FFF;
        padding: 10px;
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
        font-size: 14px;
        line-height: 23px;
        padding: 4px 0;
        text-decoration: none;
        text-shadow: none;
        border-radius: 3px;
        box-shadow: none;
        transition: 0.25s;
        display: block;
        width: 230px;
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
        .login_small {
        margin: 10px auto;
        width: 200px;
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


logged_page_small = """
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
    <script>
    function resize_me() {
        window.resizeTo(400,500);
    }
    </script>
    
	<form action="/cgi-bin/auth.py?a=z&logoff=1" method="POST">
        <div class="login_small">
        <div class="login-screen">
        <div class="app-title">
        <h2>Logged in</h2>
            as '<strong>%s</strong>'
            </br>
            <small>...</small>
        </div>
        </div>        
        </div>

        <input type="submit" onclick="resize_me()" value="Login as different user" class="btn btn-primary btn-large btn-block" ></br>
        </div>        
        </form>
</body>
"""


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

	<script>
	function dettach() {
	    var statusWindow = window.open("/cgi-bin/auth.py?status=1", "LogonStatus", "width=320,height=250");
	    statusWindow.focus();
	}
	</script>

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
        </form>
        <button type="button" onclick="dettach()" class="btn btn-large btn-block">Dettach status</button>
        </div>
        </div>
        </div>        
</body>
"""

# use class="keyboardInput" for virtual keyboard below the input field

bend_url = "http://127.0.0.1:%d/" % (64000+tenant_index)

if(ip.startswith("::ffff:")):
    ip = ip[7:]
    
try:
    if ref:
        bend = SOAPpy.SOAPProxy(bend_url)
        bend.save_referer(token,ref)
        
    if token != "0":
        tok_str = "&token="+str(token)
        
        flog.info("serving authentication page for IP %s, referer %s using token %s" % (ip,ref,token))
        
        
        print   auth_page % (style,tok_str,str(port)+"-"+tenant_name+"-"+str(tenant_index))
    else:
        if ip:
            bend = SOAPpy.SOAPProxy(bend_url)
            logon_info = bend.whois(ip)
            
            flog.debug("logon_info: " + str(logon_info))
            
            if logon_info != []:

                if logoff == "0":
                    if status > 0:
                        print logged_page_small % (style_small,logon_info[1])
                    else:
                        print logged_page % (style,logon_info[1])
                else:
                    bend.deauthenticate(ip)
                    print auth_page % (style,"0",str(port)+"-"+tenant_name+"-"+str(tenant_index))
                    
            else:
                print   auth_page % (style,"0",str(port)+"-"+tenant_name+"-"+str(tenant_index))
                

except Exception, e:
    util.print_message("Error","Error occured:", str(e),"/error.html")
    flog.error("auth.py: exception caught: " + str(e))
