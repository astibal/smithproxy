// SPDX-License-Identifier:        GPL-2.0+

#include <service/core/authpam.hpp>

#ifdef USE_PAM

namespace sx::auth {
    static int conv (int num_msg, pam_message const ** msg, pam_response ** resp, void * appdata_ptr) {

        pam_response* reply = (pam_response*) malloc(sizeof(pam_response));

        reply->resp = (char *) appdata_ptr;
        reply->resp_retcode = 0;
        *resp = reply;

        return PAM_SUCCESS;
    }


    bool pam_auth_user_pass (const char* user, const char*  pass) {

        auto& log = log::auth();

        std::string pass_str(pass);
        auto sz = pass_str.size() + 1;
        auto mem = ::malloc(sz);

        std::memset(mem, 0, sz);
        std::memcpy(mem, pass_str.data(), pass_str.size());

        struct pam_conv pamc = { conv, (void*) mem };
        pam_handle_t * pamh = nullptr;
        int retval = PAM_ABORT;

        if ((retval = pam_start ("login", user, &pamc, &pamh)) == PAM_SUCCESS) {
            retval = pam_authenticate (pamh, PAM_DISALLOW_NULL_AUTHTOK| PAM_SILENT);
        }

        if(retval != PAM_SUCCESS) {
            _war("pam authentication failed for user '%pass_str': %pass_str", user, pam_strerror(pamh, retval));

            pam_end (pamh, 0);
            return false;
        }

        auto acc = pam_acct_mgmt(pamh, PAM_DISALLOW_NULL_AUTHTOK| PAM_SILENT );
        if(acc != PAM_SUCCESS) {
            _war("pam authentication failed for user '%pass_str': %pass_str", user, pam_strerror(pamh, acc));

            pam_end (pamh, 0);
            return false;
        }

        _not("pam authentication succeeded for user '%pass_str'", user);
        pam_end(pamh, 0);
        return true;
    }
}

#endif