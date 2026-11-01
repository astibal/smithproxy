// A test-only PAM module. It is never installed or linked into either product.
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <cstring>

extern "C" int pam_sm_authenticate(pam_handle_t* handle, int, int, const char**) {
    const char* password = nullptr;
    if(pam_get_authtok(handle, PAM_AUTHTOK, &password, "Password: ") != PAM_SUCCESS || !password) {
        return PAM_AUTH_ERR;
    }
    return std::strcmp(password, "test-only-password") == 0 ? PAM_SUCCESS : PAM_AUTH_ERR;
}
extern "C" int pam_sm_setcred(pam_handle_t*, int, int, const char**) { return PAM_SUCCESS; }
extern "C" int pam_sm_acct_mgmt(pam_handle_t*, int, int count, const char** arguments) {
    if(count > 0 && std::strcmp(arguments[0], "deny") == 0) {
        return PAM_ACCT_EXPIRED;
    }
    return PAM_SUCCESS;
}
