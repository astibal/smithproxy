#pragma once

#include <log/logan.hpp>

struct CliDebugState {
    bool cli_debug_flag = false;
    const char* debug_levels =
        "\n\t0\tNONE\n\t1\tFATAL\n\t2\tCRITICAL\n\t3\tERROR\n\t4\tWARNING\n\t5\tNOTIFY"
        "\n\t6\tINFORMATIONAL\n\t7\tDIAGNOSE\t(may impact performance)"
        "\n\t8\tDEBUG\t(impacts performance)\n\t9\tEXTREME\t(severe performance drop)"
        "\n\t10\tDUMPALL\t(performance killer)\n\treset\treset back to configured level";

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

    static CliDebugState& get() {
        static thread_local CliDebugState state;
        return state;
    }
};
