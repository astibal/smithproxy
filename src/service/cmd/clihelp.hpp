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
#include <list>
#include <functional>
#include <any>
#include <optional>
#include <memory>

#include <utils/fs.hpp>
#include <utils/str.hpp>
#include <policy/addrobj.hpp>
#include <display.hpp>


using namespace libcli;

struct CliElement {

    struct filter_retval {

        filter_retval(std::string v, std::string c) :
            value(std::move(v)),
            comment(std::move(c)){};

        std::optional<std::string> value;
        std::string comment;

        static inline filter_retval accept(std::string const& v) { return filter_retval( v, std::string()); }
        static inline filter_retval accept(std::string const& v, std::string const& c) { return filter_retval( v,c); }
        static inline filter_retval reject(std::string c) {
            filter_retval v;
            v.comment = std::move(c);
            return v;
        }

        [[nodiscard]] bool accepted() const noexcept { return value.has_value(); };
        std::string get_value() const { return value.value(); }
        std::string get_comment() const { return comment; }

    private:
        explicit filter_retval(): value(std::nullopt), comment() {}
    };



    using value_filter_fn = filter_retval(std::string const&);
    using suggestion_generator_fn = std::vector<std::string>(std::string const&, std::string const&);

    CliElement() : name_("<unknown>") {};
    explicit CliElement(std::string name) : name_(std::move(name)) {}
    CliElement& operator=(CliElement const& ref) {

        if( this != &ref) {
            name_ = ref.name_;
            help_ = ref.help_;
            help_quick_ = ref.help_quick_;
            value_filter_ = ref.value_filter_;
        }
        return *this;
    };

    std::string name_;
    std::string help_;
    std::string help_quick_;
    bool may_be_empty_ = true;

    // don't use std::function as reference
    std::list<std::function<value_filter_fn>> value_filter_= { CliElement::VALUE_ANY };

    std::function<suggestion_generator_fn> gen_suggestions_ = SUGGESTION_GENERATOR_EMPTY;


    [[ nodiscard ]] std::string const& name() const { return name_; }


    CliElement& help(std::string const& s) { help_ = s; return *this; }
    [[ nodiscard ]] std::string const& help() const { return help_; }

    CliElement& help_quick(std::string const& s) { help_quick_ = s; return *this; }
    [[ nodiscard ]] std::string const& help_quick() const { return help_quick_; }

    CliElement& may_be_empty(bool s) { may_be_empty_ = s; return *this; }
    [[ nodiscard ]] bool may_be_empty() const { return may_be_empty_; }

    [[ nodiscard ]] std::list<std::function<value_filter_fn>> const& value_filter() const { return value_filter_; };
    CliElement& value_filter(std::function<value_filter_fn> v) { value_filter_.push_back(v); return *this; };

    [[ nodiscard ]] std::function<suggestion_generator_fn> suggestion_generator() const { return gen_suggestions_; }
    CliElement& suggestion_generator(std::function<suggestion_generator_fn> v) { gen_suggestions_ = v;  return *this; }
    std::vector<std::string> suggestion_generate(std::string const& section, std::string const& variable) { return std::invoke(gen_suggestions_, section, variable); };


    static inline std::function<suggestion_generator_fn> SUGGESTION_GENERATOR_EMPTY = [](std::string const& section, std::string const& variable) { return std::vector<std::string>(); };

    static inline std::function<suggestion_generator_fn> SUGGESTION_BOOL = [](std::string const& section, std::string const& variable) {
        std::vector<std::string> r {"true", "false" }; return r; };

    static inline std::function<value_filter_fn> VALUE_NONE = [](std::string const& v) -> filter_retval { return  filter_retval::reject("cannot be changed"); };

    static inline std::function<value_filter_fn> VALUE_ANY = [](std::string const& v) -> filter_retval { return filter_retval::accept(v); };

    static inline std::function<value_filter_fn> VALUE_UINT = [](std::string const& v) -> filter_retval {
        auto nv = safe_val(v);
        if(nv >= 0)
            return filter_retval::accept(v);
        else
            return filter_retval::reject("value must be non-negative integer");
    };

    static inline std::function<value_filter_fn> VALUE_UINT_NZ = [](std::string const& v) -> filter_retval {
        auto nv = safe_val(v);
        if(nv > 0)
            return filter_retval::accept(v);
        else
            return filter_retval::reject("value must be greater than zero");

    };

    static inline std::function<value_filter_fn> VALUE_FILE = [](std::string const& v) -> filter_retval {
        if(sx::fs::is_file(v)) {
            return filter_retval::accept(v);
        }

        return filter_retval::reject("value must be existing filename");
    };


    static inline std::function<value_filter_fn> VALUE_DIR = [](std::string const& v) -> filter_retval {
        if(sx::fs::is_dir(v)) {
            return filter_retval::accept(v);
        }

        return filter_retval::reject("value must be existing directory name");
    };

    static inline std::function<value_filter_fn> VALUE_BASEDIR = [](std::string const& v) -> filter_retval {
        if(sx::fs::is_basedir(v)) {
            return filter_retval::accept(v);
        }

        return filter_retval::reject("directory for the file must exist and must not be /");
    };

    static inline std::function<value_filter_fn> VALUE_BOOL = [](std::string const& v) -> filter_retval {

        std::string val = v;
        std::transform(v.begin(), v.end(), val.begin(), [](unsigned char c){ return std::toupper(c); });

        if( val == "TRUE" or val == "1" or val == "YES" or val == "T")
            return filter_retval::accept("true");
        else if ( val == "FALSE" or val == "0" or val == "NO" or val == "F")
            return filter_retval::accept( "false");
        else
            return filter_retval::reject("must be boolean: case insensitive value: [true|yes|1] | [false|no|0]");

    };

    static inline std::function<value_filter_fn> VALUE_IPHOST = [](std::string const& v) -> filter_retval {

        auto a = CidrAddress(v);
        if(a.cidr()) {
            if(std::string(cidr_numhost(a.cidr())) == "1") {
                return filter_retval::accept(v);
            } else {
                return filter_retval::reject("must be single IP address");
            }
        }
        else
            return filter_retval::reject("must be an IP address");

    };

    static inline std::function<value_filter_fn> VALUE_IPADDRESS = [](std::string const& v) -> filter_retval {

        auto a = CidrAddress(v);
        if(a.cidr()) {
            return filter_retval::accept(v);
        }
        else
            return filter_retval::reject("must be an IP address");

    };

};

struct CliHelp {

    CliHelp(CliHelp const&) = delete;
    CliHelp& operator=(CliHelp const&) = delete;

    using help_db = std::unordered_map<std::string, CliElement>;

    help_db element_help_;

    void init();
    void init_captures();

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

    std::optional<std::string> value_check(std::string const& varname, std::string const& value_argument, cli_def* cli);


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


struct CliStrings {
    static std::vector<std::string> const& config_not_applied() {

        static std::vector<std::string> r =
                {
                 " ",
                 "  Something didn't go well: running config NOT changed !!!",
                 "    Change will be visible in show config, but not written to mapped variables",
                 "    therefore 'save config' won't write them to file.",
                 "    ",
                 "    Consider running 'execute reload'  ... sorry for inconvenience."
                };

        return r;
    }

    static void cli_print(cli_def* cli, std::vector<std::string> const& vec) {
        for( auto const& r: vec) {
            ::cli_print(cli, r.c_str());
        }
    }
};


struct CmdCleaner {

    struct arg_opts_t {
        bool is_question = false;
        bool is_plain = false;
        std::string varname;
        std::vector<std::string> args;
    };

    static std::vector<std::string> dedup(std::vector<std::string>& vec_of_str)  {

        std::vector<std::string> consolidated_args;
        for(auto const& a: vec_of_str) {
            if (std::find(consolidated_args.begin(), consolidated_args.end(), a) == consolidated_args.end()) {
                consolidated_args.emplace_back(a);
            }
        }

        return consolidated_args;
    };

    static std::vector<std::string> toggle(std::vector<std::string>& original, std::vector<std::string>& toggles)  {

        std::vector<std::string> consolidated_args;

        for(auto const& a: original) {
            if (std::find(toggles.begin(),toggles.end(), a) == toggles.end()) {
                consolidated_args.emplace_back(a);
            }
        }

        for(auto const& a: toggles) {
            if (std::find(original.begin(),original.end(), a) == original.end()) {
                consolidated_args.emplace_back(a);
            }
        }

        return consolidated_args;
    };



    static arg_opts_t normalize(const char *command, char *argv[], int argc) {

        arg_opts_t to_ret;

        auto cmd = string_split(command, ' ');

        if(argc > 0) {
            to_ret.varname = cmd[cmd.size() - 1];
        } else {
            if(cmd.size() >= 2) {
                to_ret.varname = cmd[1];
            }
        }


        if(to_ret.varname == "name") {
            to_ret.is_plain = true;

            if (argc > 0) {
                for (int i = 0; i < argc; i++) {
                    auto escaped = std::string(argv[i]);
                    to_ret.args.emplace_back(escaped);
                }
            }

        } else {

            if (argc > 0) {
                for (int i = 0; i < argc; i++) {
                    auto escaped = std::string(argv[i]);
                    for (auto sub_escaped: string_split(escaped, ',')) {

                        sx::str::string_cfg_escape(sub_escaped);
                        to_ret.args.emplace_back(sub_escaped);
                    }
                }
                to_ret.is_question = (to_ret.args[0] == "?");

            } else {
                if (cmd.size() > 2) {
                    for (unsigned int i = 2; i < cmd.size(); i++) {

                        auto escaped = std::string(cmd[i]);
                        for (auto sub_escaped: string_split(escaped, ',')) {

                            sx::str::string_cfg_escape(sub_escaped);
                            to_ret.args.emplace_back(sub_escaped);
                        }
                    }

                    to_ret.is_question = (to_ret.args[0] == "?");
                }
            }
        }

        to_ret.args = to_ret.is_plain ? to_ret.args : dedup(to_ret.args);

        return to_ret;
    };


};

#endif //SMITHPROXY_CLIHELP_HPP
