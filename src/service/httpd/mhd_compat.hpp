#pragma once

#include <microhttpd.h>

// RFC 9110 renamed status 422. Older libmicrohttpd lacks the new name;
// newer releases deprecate the old one, which fails builds with -Werror.
#ifndef MHD_HTTP_UNPROCESSABLE_CONTENT
#define MHD_HTTP_UNPROCESSABLE_CONTENT 422
#endif
