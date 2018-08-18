#pragma once

#ifdef CPPHTTPLIB_IOCP_SUPPORT

#include <winsock2.h>
#include <MSWSock.h>

#define DEFAULT_PORT        "5001"
#define MAX_BUFF_SIZE       8192
#define MAX_WORKER_THREAD   16

namespace httplib {
	class Server;
};

enum _IO_OPERATION {
	ClientIoAccept,
	ClientIoRead,
	ClientIoWrite
};

typedef _IO_OPERATION IO_OPERATION, *PIO_OPERATION;

//
// data to be associated for every I/O operation on a socket
//
struct _PER_IO_CONTEXT {
	WSAOVERLAPPED               Overlapped;
	char                        Buffer[MAX_BUFF_SIZE];
	WSABUF                      wsabuf;
	int                         nTotalBytes;
	int                         nSentBytes;
	IO_OPERATION                IOOperation;
	SOCKET                      SocketAccept;
	struct _PER_IO_CONTEXT      *pIOContextForward;
};

typedef _PER_IO_CONTEXT PER_IO_CONTEXT, *PPER_IO_CONTEXT;
//
// For AcceptEx, the IOCP key is the PER_SOCKET_CONTEXT for the listening socket,
// so we need to another field SocketAccept in PER_IO_CONTEXT. When the outstanding
// AcceptEx completes, this field is our connection socket handle.
//

//
// data to be associated with every socket added to the IOCP
//
struct _PER_SOCKET_CONTEXT {
	SOCKET                      Socket;
	LPFN_ACCEPTEX               fnAcceptEx;
	httplib::Server			    *lpIOCPServer;

	//
	//linked list for all outstanding i/o on the socket
	//
	PPER_IO_CONTEXT             pIOContext;
	struct _PER_SOCKET_CONTEXT  *pCtxtBack;
	struct _PER_SOCKET_CONTEXT  *pCtxtForward;
};

typedef _PER_SOCKET_CONTEXT PER_SOCKET_CONTEXT, *PPER_SOCKET_CONTEXT;
#endif