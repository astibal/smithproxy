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

import logging
import struct

from shmtable import ShmTable

flog = logging.getLogger('bend')


class TokenTable(ShmTable):
    def __init__(self):
        ShmTable.__init__(self, 576)
        self.tokens = {}  # token => url
        self.used_tokens = []  # used throw here - delete when appropriate
        self.active_queue = []  # add everything here. After size grows to some point, start
        # deleting also active unused yed tokens

        self.delete_used_threshold = 5  # 1 means immediately
        self.delete_active_threshold = 200  # mark oldest tokens above this margin as used
        self.normalize = False

    def on_new_table(self):
        ShmTable.on_new_table(self)
        self.tokens = {}

    def on_new_entry(self, blob):
        ShmTable.on_new_entry(self, blob)
        t, u = struct.unpack('64s512s', blob)

        t_i = t.find('\x00', 0, 512)
        u_i = u.find('\x00', 0, 512)
        tt = t[:t_i]
        uu = u[:u_i]

        flog.debug("TokenTable::on_new_entry: " + tt + ":" + uu)
        self.tokens[tt] = uu
        self.life_queue(tt)

    def toggle_used(self, token):
        self.used_tokens.append(token)
        if len(self.used_tokens) > self.delete_used_threshold:

            # delete all used tokens from DB
            for t in self.used_tokens:
                flog.debug("toggle_used: wiping used token " + t)
                self.tokens.pop(t, None)

            self.used_tokens = []
            self.save(True)

    def life_queue(self, token):
        self.active_queue.append(token)

        while len(self.active_queue) > self.delete_active_threshold:
            oldest_token = self.active_queue[0]
            flog.debug("life_queue: too many active tokens, dropping oldest one " + oldest_token)
            self.toggle_used(oldest_token)
            self.active_queue = self.active_queue[1:]

    def save(self, inc_version=False):
        self.seek(0)
        self.clear()
        self.write_header(inc_version, len(self.tokens.keys()))

        write_cnt = 0
        for k in self.tokens.keys():
            try:
                self.write(struct.pack("64s512s", k, self.tokens[k]))
                write_cnt = write_cnt + 1
            except IndexError:
                continue

        flog.debug("save: %d tokens written to table" % (write_cnt,))

        self.normalize = False  # each dump effectively normalizes db
