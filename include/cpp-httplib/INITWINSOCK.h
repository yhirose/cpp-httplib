#pragma once

#ifdef _WIN32

#include <WinSock2.h>

class WSInit {
public:
    WSInit() {
        WSADATA wsaData;
        WSAStartup(0x0002, &wsaData);
    }

    ~WSInit() {
        WSACleanup();
    }
};

static WSInit wsinit_;

#endif