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

#ifndef _STATICCONTENT_HPP
 #define _STATICCONTENT_HPP

#include <sobject.hpp>
#include <ptr_cache.hpp>
#include <ext/nltemplate/nltemplate.hpp>

using namespace ext::nltemplate;

class StaticContent {

    std::unique_ptr<ptr_cache<std::string,Template>> templates_;
    StaticContent() {
        templates_ = std::make_unique<ptr_cache<std::string,Template>>("content.replacements");

    };
    ~StaticContent() = default;

    logan_lite& log = get_log();
    std::mutex lock;
public:
    // should be populated externally, on start
    static inline uint32_t boot_random {0};

    bool load_files(std::string& dir);
    
    std::string render_noargs(std::string const& s);

    std::string render_server_response(std::string const& message, unsigned int code=200);
    std::string render_msg_html_page(std::string const& caption, std::string const& meta, std::string const& content,const char* window_width="450px");
    std::shared_ptr<Template> get(std::string const& s);

    static StaticContent* get() {
        static StaticContent s;
        return &s;
    };

    static logan_lite& get_log() {
        static logan_lite l("renderer");
        return l;
    }
};

inline StaticContent* html() { return StaticContent::get(); }
#endif