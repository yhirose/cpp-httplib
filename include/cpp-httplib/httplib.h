//
//  httplib.h
//
//  Copyright (c) 2017 Yuji Hirose. All rights reserved.
//  MIT License
//
#pragma once



//Simply including this file
//does the WSAStartup routine
//on Windows platform, fire and forget!
#include "INITWINSOCK.h"

//initialize openssl things the same way!
#include "SSLINIT.h"



//The http server class
#include "Server.h"

//The http client class
#include "Client.h"

//SSL Client class
#include "SSLClient.h"

//SSL Server class
#include "SSLServer.h"



//Class encapsulating http requests
#include "Request.h"

//Class encapsulating http responses
#include "Response.h"








