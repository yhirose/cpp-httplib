#pragma once

#ifdef _WIN32

#ifdef CPPHTTPLIB_IOCP_SUPPORT
#pragma warning (disable:4127)

#ifdef _IA64_
#pragma warning(disable:4267)
#endif 

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#endif

#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif

#ifndef _CRT_NONSTDC_NO_DEPRECATE
#define _CRT_NONSTDC_NO_DEPRECATE
#endif

#if defined(_MSC_VER) && _MSC_VER < 1900
#define snprintf _snprintf_s
#endif

#undef min
#undef max

#ifndef strcasecmp
#define strcasecmp _stricmp
#endif

#endif