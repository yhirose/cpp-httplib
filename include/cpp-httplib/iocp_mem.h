#pragma once

#ifdef CPPHTTPLIB_IOCP_SUPPORT

#include <Windows.h>

#define xmalloc(s) HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,(s))
#define xfree(p) HeapFree(GetProcessHeap(),0,(p))

#endif