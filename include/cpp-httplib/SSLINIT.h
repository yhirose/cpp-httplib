#pragma once

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT

#include <openssl/ssl.h>

class SSLInit {
public:
    SSLInit() {
        SSL_load_error_strings();
        SSL_library_init();
    }
};

static SSLInit sslinit_;

#endif