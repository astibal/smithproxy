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
    <style media="screen" type="text/css">
        * {
        box-sizing: border-box;
        }
        
        *:focus {
        outline: none;
        }
        body {
        font-family: Arial;
        background-color: #3498DB;
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
</head>
<body>

<form action="/cgi-bin/auth2.py?a=z%s" method="POST">
 <div class="login">
 <div class="login-screen">
 <div class="app-title">
 <h2>Authentication required</h2>
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

# use class="keyboardInput" for virtual keyboard below the input field

try:
    if token:
        tok_str = "&token="+str(token)
        print page % (tok_str,)
    else:
        print page % ("0",)
        
    if ref:
        bend = SOAPpy.SOAPProxy("http://localhost:65456/")
        bend.save_referer(token,ref)

except Exception, e:
    util.print_message("Error","Error occured:", str(e),"/error.html")
    logging.error("auth.py: exception caught: " + str(e))

