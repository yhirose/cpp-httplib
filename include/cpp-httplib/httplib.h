//
//  httplib.h
//
//  Copyright (c) 2017 Yuji Hirose. All rights reserved.
//  MIT License
//
#pragma once

//pre processor directives to set
//up compiler, etc.
//
//always comes first!
#include "pure_preprocessor.h"



//Simply including this file
//does the WSAStartup routine
//on Windows platform, fire and forget!
#include "INITWINSOCK.h"

//initialize openssl things the same way!
#include "SSLINIT.h"



//malloc and free macro for iocp
#include "iocp_mem.h"



//httplib and detail namespace typedefs
#include "httplib_typedefs.h"

//Custom Overlapped IO Context Structs
//and iocp enum
#include "iocp_types.h"



//code shared between classes
#include "detail.h"



//The http server class
#include "Server.h"

//The http client class
#include "Client.h"

//SSL Client class
#include "SSLClient.h"

//SSL Server class
#include "SSLServer.h"



//Abstract base class for streams
//e.g. Subclass this to integrate new
//set of socket calls for process_request
//process_response
#include "Stream.h"

//socket stream class
#include "SocketStream.h"

//SSL socket stream class
#include "SSLSocketStream.h"

//stream for iocp support
#include "IOCPStream.h"

//class to get lines from streams
//and build buffers
#include "stream_line_reader.h"



//Class encapsulating http requests
#include "Request.h"

//Class encapsulating http responses
#include "Response.h"








