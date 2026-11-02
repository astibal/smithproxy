#include "pam_backend.hpp"

#include <security/pam_appl.h>
#include <grp.h>
#include <pwd.h>
#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <stdexcept>

namespace sx::auth {
namespace {
int conversation(int count, const pam_message** messages, pam_response** output, void* context) {
    if(count < 1 || count > 32 || !messages || !output || !context) {
        return PAM_CONV_ERR;
    }
    const auto& credentials = *static_cast<PapCredentials*>(context);
    auto* replies = static_cast<pam_response*>(std::calloc(count, sizeof(pam_response)));
    if(!replies) {
        return PAM_BUF_ERR;
    }

    for(int index = 0; index < count; ++index) {
        const char* answer = nullptr;
        if(messages[index]) {
            switch(messages[index]->msg_style) {
                case PAM_PROMPT_ECHO_OFF: answer = credentials.password.c_str(); break;
                case PAM_PROMPT_ECHO_ON: answer = credentials.username.c_str(); break;
                case PAM_TEXT_INFO:
                case PAM_ERROR_MSG: continue;
                default: break;
            }
        }
        if(answer) {
            replies[index].resp = ::strdup(answer);
        }
        if(!answer || !replies[index].resp) {
            for(int prior = 0; prior <= index; ++prior) {
                std::free(replies[prior].resp);
            }
            std::free(replies);
            return PAM_CONV_ERR;
        }
    }
    *output = replies;
    return PAM_SUCCESS;
}

bool member_of(const std::string& username, const std::string& group_name) {
    passwd user{};
    passwd* found_user = nullptr;
    group target{};
    group* found_group = nullptr;
    std::vector<char> user_buffer(65536);
    std::vector<char> group_buffer(65536);
    if(getpwnam_r(username.c_str(), &user, user_buffer.data(), user_buffer.size(), &found_user) != 0 ||
       !found_user || getgrnam_r(group_name.c_str(), &target, group_buffer.data(),
                                 group_buffer.size(), &found_group) != 0 || !found_group) {
        return false;
    }

    // NSS may resolve remote identities too. Include the primary group and
    // supplementary groups, while bounding the storage for a single lookup.
    int count = 64;
    std::vector<gid_t> groups(count);
    if(getgrouplist(username.c_str(), user.pw_gid, groups.data(), &count) < 0) {
        if(count < 1 || count > 65536) {
            return false;
        }
        groups.resize(count);
        if(getgrouplist(username.c_str(), user.pw_gid, groups.data(), &count) < 0) {
            return false;
        }
    }
    return std::find(groups.begin(), groups.begin() + count, target.gr_gid) != groups.begin() + count;
}
}

LinuxPamBackend::LinuxPamBackend(std::string service, std::string allowed_group, std::string config_directory)
    : service_(std::move(service)), allowed_group_(std::move(allowed_group)),
      config_directory_(std::move(config_directory)) {
    if(service_.empty() || service_.size() > 128 ||
       service_.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.") != std::string::npos ||
       allowed_group_.empty() || allowed_group_.size() > 255 ||
       allowed_group_.find('\0') != std::string::npos ||
       (!config_directory_.empty() && config_directory_.front() != '/') ||
       config_directory_.find('\0') != std::string::npos) {
        throw std::invalid_argument("PAM service and allowed group are required");
    }
}

std::optional<Result> LinuxPamBackend::verify_pap(PapCredentials credentials, completion_type) {
    if(credentials.username.empty() || credentials.username.size() > 255 ||
       credentials.password.empty() || credentials.password.size() > 1024 ||
       credentials.username.find('\0') != std::string::npos ||
       credentials.password.find('\0') != std::string::npos) {
        return Result{Status::rejected, {}, {}};
    }

    pam_conv callbacks{conversation, &credentials};
    pam_handle_t* handle = nullptr;
    int result = config_directory_.empty()
        ? pam_start(service_.c_str(), credentials.username.c_str(), &callbacks, &handle)
        : pam_start_confdir(service_.c_str(), credentials.username.c_str(), &callbacks,
                            config_directory_.c_str(), &handle);
    if(result != PAM_SUCCESS) {
        if(handle) {
            pam_end(handle, result);
        }
        return Result{Status::error, {}, "PAM initialization failed"};
    }
    auto cleanup = std::unique_ptr<pam_handle_t, void(*)(pam_handle_t*)>(handle, [](pam_handle_t* value) {
        pam_end(value, PAM_SUCCESS);
    });

    result = pam_authenticate(handle, PAM_DISALLOW_NULL_AUTHTOK | PAM_SILENT);
    if(result == PAM_SUCCESS) {
        result = pam_acct_mgmt(handle, PAM_SILENT);
    }
    if(result != PAM_SUCCESS) {
        return Result{Status::rejected, {}, {}};
    }

    // PAM may canonicalize the identity. Group policy must use that identity,
    // not the name supplied before the PAM stack ran.
    const void* canonical = nullptr;
    if(pam_get_item(handle, PAM_USER, &canonical) != PAM_SUCCESS || !canonical) {
        return Result{Status::error, {}, "PAM returned no identity"};
    }
    std::string identity(static_cast<const char*>(canonical));
    if(identity.empty() || identity.size() > 255 || !member_of(identity, allowed_group_)) {
        return Result{Status::rejected, {}, {}};
    }
    Result accepted{Status::accepted, std::move(identity), {}};
    accepted.groups.push_back(allowed_group_);
    return accepted;
}
} // namespace sx::auth
