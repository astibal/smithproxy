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

#include <regex>

#include <display.hpp>
#include <utils/str.hpp>

namespace  sx::str {
    void string_replace_all (std::string &target, std::string const &what, std::string const &replacement) {

        if(what.empty() or target.empty()) return;

        for(auto pos = target.find(what); pos != std::string::npos; ) {

            // Replace this occurrence of Sub String
            target.replace(pos, what.size(), replacement);
            // Get the next occurrence from the current position
            pos = target.find(what, pos + replacement.size());
        }
    }

    void string_cfg_escape (std::string &target) {
        string_replace_all(target, "'", "_");
        string_replace_all(target, "\\", "_");
        string_replace_all(target, "%", "_");
        string_replace_all(target, ";", "_");
        string_replace_all(target, ":", "_");
        string_replace_all(target, ",", "_");
        string_replace_all(target, "\"", "_");
        string_replace_all(target, "{", "_");
        string_replace_all(target, "}", "_");
        string_replace_all(target, "[", "_");
        string_replace_all(target, "]", "_");
        string_replace_all(target, "(", "_");
        string_replace_all(target, ")", "_");
    }

    namespace cli {

        static std::regex re_index() {
            static auto r = std::regex("\\[[0-9]+\\]");
            return r;
        }
        // helpers for cli processing

        std::string mask_array_index(std::string const& varname) {
            return std::regex_replace (varname, re_index(), "[x]");
        }

        std::string mask_parent(std::string const& varname) {
            // another attempt - find parent setting mask
            auto path_split = string_split(varname, '.');


            // make test only if depth is 3 or more:   category1[.categoryX., ..].<to_mask>.varname
            if(path_split.size() >= 3) {

                std::string masked_parent = path_split[0];

                unsigned int i = 1;
                for (auto const &elem: path_split) {

                    if(i == 1) {
                        i++;
                        continue;
                    }
                    else if (i == path_split.size() - 1) {
                        masked_parent += ".[x]";
                    } else {
                        masked_parent += "." + elem;
                    }
                    i++;
                }

                return masked_parent;
            }

            return varname;
        }
    }

}