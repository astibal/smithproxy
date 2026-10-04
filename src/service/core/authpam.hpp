// SPDX-License-Identifier:        GPL-2.0+

#ifndef AUHTPAM_HPP_
#define AUHTPAM_HPP_

#ifdef USE_PAM

#include <security/pam_appl.h>
#include <security/pam_misc.h>

#include <log/logan.hpp>

namespace sx::auth {

    namespace log {
        static logan_lite& auth() {
            static auto s = logan_lite("auth");
            return s;
        }
    }

    bool pam_auth_user_pass (const char* user, const char*  pass);
    bool unix_is_group_member(const char* username, const char* groupname);
}

#endif

#endif
