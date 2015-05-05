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

import string

def print_message(pagename,caption,message,redirect_url=None,redirect_time=5):
        print "Content-type:text/html\r\n\r\n"

        page = """
        <html>
        <head>
                <title>$pagename</title>
                <META HTTP-EQUIV="Content-Type" CONTENT="text/html; charset=utf-8">
                $redirect_meta
        </head>
        <body>
        <div>
        <tablealign="center">
        <tr><th colspan="2">$caption</th></tr>
        <tr><td>
        $message
        </td></tr>
        </table>
        </div>
        </body> 
        </html> 
        """
        	
        t = string.Template(page)
        if redirect_url != None:
            meta = "<meta http-equiv=\"Refresh\" content=\"%d; url=%s\">" % (redirect_time, redirect_url)
            print t.substitute(pagename=pagename, caption=caption, message=message, redirect_meta=meta)
            return

        print t.substitute(pagename=pagename, caption=caption, message=message, redirect_meta="")

