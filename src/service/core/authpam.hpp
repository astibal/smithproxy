// SPDX-License-Identifier:        GPL-2.0+

#ifndef AUHTPAM_HPP_
#define AUHTPAM_HPP_

#include <security/pam_appl.h>
#include <security/pam_misc.h>

#include <log/logan.hpp>

#ifdef USE_PAM

namespace sx::auth {

    namespace log {
        static logan_lite& auth() {
            static auto s = logan_lite("auth");
            return s;
        }
    }

    bool pam_auth_user_pass (const char* user, const char*  pass);
}

#endif

#endif