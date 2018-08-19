#pragma once

#ifdef CPPHTTPLIB_IOCP_SUPPORT

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#define xmalloc(s) HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,(s))
#define xfree(p) HeapFree(GetProcessHeap(),0,(p))

#endif