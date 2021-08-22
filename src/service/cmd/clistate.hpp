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

#ifndef _CLISTATE_HPP_
#define _CLISTATE_HPP_



#include <ext/libcli/libcli.h>
#include <service/cmd/clihelp.hpp>
#include <log/logan.hpp>


struct CliCallbacks {

    CliCallbacks() : caption_("<unknown>") {};
    explicit CliCallbacks(std::string c) : caption_(std::move(c)) {};

    using callback = int (*)(struct cli_def *,const char *,char * *,int);

    callback cmd(std::string const& key) {
        return  get_cmdlet(key).cb_;
    }
    CliCallbacks& cmd(std::string const& key, callback c) {
        get_cmdlet(key).cb_ = c;
        return *this;
    }

    cli_command* cli(std::string const& key) {
        return get_cmdlet(key).cli_;
    };

    CliCallbacks& cli(std::string const& key, cli_command* c) {
        get_cmdlet(key).cli_ = c;
        return *this;
    }

    [[nodiscard]] bool cap(std::string const& key) {
        return get_cmdlet(key).enabled_;
    };
    CliCallbacks& cap(std::string const& key, bool v) {
        get_cmdlet(key).enabled_ = v;
        return *this;
    }


    struct cmdlet_t {
        std::string name_;
        bool enabled_ = false;
        callback cb_ = nullptr;
        cli_command* cli_  = nullptr;
    };

private:
    std::string caption_;
    std::vector<cmdlet_t> cmdlets_;

    cmdlet_t& get_cmdlet(std::string const& key) {


        for(auto& ref: cmdlets_) {
            if (ref.name_ == key) {
                return ref;
            }
        }

        // not found, create
        cmdlet_t n = { .name_ = key };

        cmdlets_.push_back(n);
        return cmdlets_.back();
    }
};


struct CliGlobalState {
    CliGlobalState() = delete;
    CliGlobalState(CliGlobalState const&) = delete;
    CliGlobalState&operator=(CliGlobalState&) = delete;

    static inline bool config_changed_flag = false;
};

struct CliState {
    bool cli_debug_flag = false;

    int cli_port = 50000;
    int cli_port_base = 50000;
    std::string cli_enable_password;


    const char *debug_levels = "\n\t0\tNONE\n\t1\tFATAL\n\t2\tCRITICAL\n\t3\tERROR\n\t4\tWARNING\n\t5\tNOTIFY\n\t6\tINFORMATIONAL\n\t7\tDIAGNOSE\t(may impact performance)\n\t8\tDEBUG\t(impacts performance)\n\t9\tEXTREME\t(severe performance drop)\n\t10\tDUMPALL\t(performance killer)\n\treset\treset back to level configured in config file";

    loglevel orig_ssl_loglevel = NON;
    loglevel orig_sslmitm_loglevel = NON;
    loglevel orig_sslca_loglevel = NON;

    loglevel orig_dns_insp_loglevel = NON;
    loglevel orig_dns_packet_loglevel = NON;

    loglevel orig_baseproxy_loglevel = NON;
    loglevel orig_epoll_loglevel = NON;
    loglevel orig_mitmproxy_loglevel = NON;
    loglevel orig_mitmmasterproxy_loglevel = NON;

    loglevel orig_mitmhostcx_loglevel = NON;
    loglevel orig_socksproxy_loglevel = NON;

    loglevel orig_auth_loglevel = NON;

    static CliState& get() {
        static thread_local CliState c;
        return c;
    }

    static CliHelp& help() {
        return get().help_;
    }

    CliState(CliState const&) = delete;
    CliState& operator=(CliState const&) = delete;

    // command callbacks
    using callback = CliCallbacks;

    using callback_entry = std::tuple<unsigned int, callback>;


    callback_entry& callbacks(std::string const& s) {
        return callback_map_[s];
    }

    bool erase_callback(std::string const& s) {
        return callback_map_.erase(s) > 0;
    }

    bool has_callback(std::string const& s) {
        return callback_map_.find(s) != callback_map_.end();
    }

    std::string sections(int mode) {
        return mode_map[mode];
    }

    std::string template_callback_key(std::string const& section, cli_def* cli = nullptr);

    void callbacks(std::string const& s, callback_entry v, bool set_mode_map = true) {
        callback_map_[s] = v;            //map SETTING => CALLBACKS

        if(set_mode_map)
            mode_map[std::get<0>(v)] = s; //map MODE => SETTING
    }

private:

    std::unordered_map<std::string, callback_entry> callback_map_;
    std::unordered_map<int, std::string> mode_map;

    CliState() : help_(CliHelp::get()) {};
    CliHelp& help_;
};


#endif