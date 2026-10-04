// SPDX-License-Identifier:        GPL-2.0+

#include <service/core/authpam.hpp>

#ifdef USE_PAM

#include <pwd.h>
#include <grp.h>

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <vector>

namespace sx::auth {
    static int conv (int num_msg, pam_message const ** msg, pam_response ** resp, void * appdata_ptr) {
        if (num_msg <= 0 || msg == nullptr || resp == nullptr || appdata_ptr == nullptr)
            return PAM_CONV_ERR;

        auto* replies = static_cast<pam_response*>(calloc(static_cast<size_t>(num_msg),
                                                          sizeof(pam_response)));
        if (replies == nullptr) return PAM_BUF_ERR;

        auto const* password = static_cast<char const*>(appdata_ptr);
        for (int i = 0; i < num_msg; ++i) {
            if (msg[i] == nullptr) {
                free(replies);
                return PAM_CONV_ERR;
            }
            switch (msg[i]->msg_style) {
                case PAM_PROMPT_ECHO_OFF:
                    replies[i].resp = strdup(password);
                    if (replies[i].resp == nullptr) {
                        for (int j = 0; j < i; ++j) free(replies[j].resp);
                        free(replies);
                        return PAM_BUF_ERR;
                    }
                    break;
                case PAM_ERROR_MSG:
                case PAM_TEXT_INFO:
                    break;
                default:
                    for (int j = 0; j < i; ++j) free(replies[j].resp);
                    free(replies);
                    return PAM_CONV_ERR;
            }
        }

        *resp = replies;
        return PAM_SUCCESS;
    }


    bool pam_auth_user_pass (const char* user, const char*  pass) {

        if (user == nullptr || pass == nullptr || *user == '\0') return false;

        auto& log = log::auth();

        struct pam_conv pamc = { conv, const_cast<char*>(pass) };
        pam_handle_t * pamh = nullptr;
        int retval = PAM_ABORT;

        if ((retval = pam_start ("login", user, &pamc, &pamh)) == PAM_SUCCESS) {
            retval = pam_authenticate (pamh, PAM_DISALLOW_NULL_AUTHTOK| PAM_SILENT);
        }

        if(retval != PAM_SUCCESS) {
            auto const* error = pamh == nullptr ? "pam_start failed" : pam_strerror(pamh, retval);
            _war("pam authentication failed for user '%s': %s", user, error);

            if (pamh != nullptr) pam_end(pamh, retval);
            return false;
        }

        auto acc = pam_acct_mgmt(pamh, PAM_DISALLOW_NULL_AUTHTOK| PAM_SILENT );
        if(acc != PAM_SUCCESS) {
            _war("pam authentication failed for user '%s': %s", user, pam_strerror(pamh, acc));

            pam_end(pamh, acc);
            return false;
        }

        _not("pam authentication succeeded for user '%s'", user);
        pam_end(pamh, 0);
        return true;
    }

    bool unix_is_group_member(const char* username, const char* groupname) {

        if (username == nullptr || groupname == nullptr ||
            *username == '\0' || *groupname == '\0') return false;

        struct passwd pw{};
        struct passwd* pwd_result = nullptr;
        auto pwd_size = sysconf(_SC_GETPW_R_SIZE_MAX);
        std::vector<char> pwd_buffer(pwd_size > 0 ? static_cast<size_t>(pwd_size) : 16384U);
        auto pw_ret = getpwnam_r(username, &pw, pwd_buffer.data(), pwd_buffer.size(), &pwd_result);
        if (pw_ret != 0 || pwd_result == nullptr) return false;

        struct group target_group{};
        struct group* group_result = nullptr;
        auto group_size = sysconf(_SC_GETGR_R_SIZE_MAX);
        std::vector<char> group_buffer(group_size > 0 ? static_cast<size_t>(group_size) : 16384U);
        auto group_ret = getgrnam_r(groupname, &target_group, group_buffer.data(),
                                    group_buffer.size(), &group_result);
        if (group_ret != 0 || group_result == nullptr) return false;

        int ngroups = 0;
        (void)getgrouplist(username, pw.pw_gid, nullptr, &ngroups);
        if (ngroups <= 0) return false;

        std::vector<gid_t> groups(static_cast<size_t>(ngroups));
        if (getgrouplist(username, pw.pw_gid, groups.data(), &ngroups) == -1) return false;

        bool to_ret = false;

        // iterate all groups to avoid side channel
        for (int j = 0; j < ngroups; j++) {
            if (groups[static_cast<size_t>(j)] == target_group.gr_gid) to_ret = true;
        }

        return to_ret;
    }

}

#endif
