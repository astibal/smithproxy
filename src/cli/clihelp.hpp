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

#ifndef SMITHPROXY_CLIHELP_HPP

#define SMITHPROXY_CLIHELP_HPP

#include <unordered_map>
#include <string>
#include <functional>

struct CliElement {

    CliElement() : name_("<unknown>") {};
    explicit CliElement(std::string const& name) : name_(name) {}
    std::string name_;
    std::string const& name() const { return name_; }

    std::string help_;
    std::string help_quick_ = "";

    CliElement& help(std::string const& s) { help_ = s; return *this; }
    std::string const& help() const { return help_; }

    CliElement& help_quick(std::string const& s) { help_quick_ = s; return *this; }
    std::string const& help_quick() const { return help_quick_; }

    bool may_be_empty_ = true;
    CliElement& may_be_empty(bool s) { may_be_empty_ = s; return *this; }
    bool may_be_empty() const { return may_be_empty_; }

};

struct CliHelp {

    CliHelp(CliHelp const&) = delete;
    CliHelp& operator=(CliHelp const&) = delete;

    using help_db = std::unordered_map<std::string, CliElement>;

    help_db element_help_;

    void init();

    std::optional<std::reference_wrapper<CliElement>> find(std::string const& k) {

        if(element_help_.find(k) != element_help_.end()) {
            return std::ref(element_help_[k]);
        }

        return std::nullopt;
    }

    CliElement& add(std::string const& k, std::string v ) {

        element_help_[k] = CliElement(k);
        element_help_[k].help_ = v;
        return element_help_[k];
    }

    CliElement& help_quick(std::string const& k, std::string v ) {
        return element_help_[k].help_quick(v);
    }

    bool value_check(std::string const& varname, int v, cli_def* cli);
    bool value_check(std::string const& varname, long long int v, cli_def* cli);
    bool value_check(std::string const& varname, bool v, cli_def* cli);
    bool value_check(std::string const& varname, float v, cli_def* cli);
    bool value_check(std::string const& varname, std::string const& v, cli_def* cli);


    enum class help_type_t { HELP_CONTEXT=0, HELP_QMARK };
    using help_type_t = help_type_t;

    std::string help(help_type_t htype, const std::string& section, const std::string& key);


    static CliHelp& get() {
        static CliHelp h;
        return h;
    }

private:
    CliHelp() {
        init();
    }
};


#endif //SMITHPROXY_CLIHELP_HPP
