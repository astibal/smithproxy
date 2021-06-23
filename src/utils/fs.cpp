/*
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
*/

#include <libgen.h>

#include <utils/fs.hpp>
#include <utils/mem.hpp>
#include <log/logan.hpp>


namespace sx::fs {

    static logan_lite& get_log() {
        static logan_lite log_("utils.fs");
        return log_;
    }


    bool is_dir(std::string const& v) {
        auto log = sx::fs::get_log();

        if (  struct stat sb{} ; ::stat(v.c_str(), &sb) >= 0) {
            _deb("is_dir: '%s' exists", v.c_str());
            if ((sb.st_mode & S_IFMT) == S_IFDIR) {
                _deb("is_dir: '%s' is directory", v.c_str());
                return true;
            } else {
                _deb("is_dir: '%s' is not directory", v.c_str());
            }
        } else {
            _deb("is_dir: '%s' does not exist", v.c_str());
        }

        return false;
    }

    bool is_file(std::string const& v) {
        auto log = sx::fs::get_log();

        if (struct stat sb{}; ::stat(v.c_str(), &sb) >= 0) {
            _deb("is_file: '%s' exists", v.c_str());
            if ((sb.st_mode & S_IFMT) == S_IFREG) {
                _deb("is_file: '%s' is file", v.c_str());
                return true;
            }
            else {
                _deb("is_file: '%s' is not file", v.c_str());
            }
        } else {
            _deb("is_file: '%s' does not exist", v.c_str());
        }

        return false;
    }

    bool is_basedir(std::string const& v) {
        auto log = sx::fs::get_log();

        auto path = sx::mem::unique_mpool_alloc(v.size());

        if(is_dir(v) or v.empty()) {
            // it supposed to be a file, not a directory or nothing
            _deb("is_basedir: '%s' is empty or is directory (expecting file path)", v.c_str());
            return false;
        }

        std::memcpy(path.get(), v.c_str(), v.size());

        for(auto i = v.size() - 1; i <= 0; i--) {
            if(path.get()[i] == '/') {
                path.get()[i] = '\x00';
                continue;
            }

            _deb("is_basedir: '%s' removed %d trailing /", v.c_str(), i);
            break;
        }

        std::string dir_path = dirname((char *) path.get());
        if(dir_path == "/") {
            // bit too many of traversals
            _deb("is_basedir: '%s' dirname is / - refusing to place files there", v.c_str());
            return false;
        }

        auto r = is_dir(dir_path);

        _deb("is_basedir: '%s' returning %d", v.c_str(), r);

        return r;
    }
}