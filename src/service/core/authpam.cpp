// SPDX-License-Identifier:        GPL-2.0+

#include <service/core/authpam.hpp>

#ifdef USE_PAM

#include <pwd.h>
#include <grp.h>

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

    bool unix_is_group_member(const char* username, const char* groupname) {

        int ngroups = 64;
        auto *groups = (gid_t*) malloc(sizeof(gid_t) * ngroups);
        raw::guard grp_mem([&](){ free(groups); });

        if (groups == nullptr) {
            return false;
        }

        struct passwd pw;
        struct passwd* pwd_ptr = &pw;
        struct passwd* temp_pwd_ptr;

        char pwd_buffer[200];
        int  pwd_bufsz = sizeof(pwd_buffer);

        auto pw_ret = getpwnam_r(username,pwd_ptr,pwd_buffer,pwd_bufsz,&temp_pwd_ptr);
        if (pw_ret != 0) {
            return false;
        }

        if (getgrouplist(username, pw.pw_gid, groups, &ngroups) == -1) {
            return false;
        }

        bool to_ret = false;

        // iterate all groups to avoid side channel
        for (int j = 0; j < ngroups; j++) {

            struct group  gr{};
            struct group* gr_ptr = &gr;
            struct group* temp_gr_ptr;

            char grp_buffer[200];
            int grp_bufsz = sizeof(grp_buffer);


            int gr_result = getgrgid_r(groups[j], gr_ptr, grp_buffer, grp_bufsz, &temp_gr_ptr);
            if (gr_result == 0) {
                auto gr_string = std::string (gr.gr_name);
                if(gr_string == groupname) {
                    to_ret = true;
                }
            }
        }

        return to_ret;
    }

}

#endif