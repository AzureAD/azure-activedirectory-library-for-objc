//+-------------------------------------------------------------------------
//
//  Microsoft Windows
//
//  Copyright (C) Microsoft Corporation, 1996 - 2013
//
//  File:       port.h
//
//  Contents:   Definitions for port of hash.c 
//
//  History:    06-18-2013   jmackay created
//                           danshu merging with previous port headers
//
//--------------------------------------------------------------------------
#ifndef __PORT_H__
#define __PORT_H__

#include <stdlib.h>
#include <stdint.h>

// "windows.h" defines and typedefs
#define TRUE 1
#define FALSE 0
//typedef int BOOL, *PBOOL, *LPBOOL;
typedef unsigned char BYTE, *PBYTE, *LPBYTE;

typedef unsigned char UCHAR, *PUCHAR; 

typedef wchar_t* LPWSTR, *PWSTR; 
typedef const wchar_t* LPCWSTR; 

typedef wchar_t WCHAR, *PWCHAR; 
typedef void VOID, *PVOID, *LPVOID;
typedef void* HANDLE;
#define FAR
#define far

#if defined(__APPLE__) || defined(__ANDROID_API__)
typedef uint64_t ULONGLONG;

typedef int32_t LONG;
typedef LONG *PLONG, *LPLONG;

typedef uint32_t ULONG;
typedef ULONG *PULONG; 

typedef uint32_t DWORD;
typedef DWORD *PDWORD, *LPDWORD;

#else
typedef unsigned __int64 ULONGLONG;

typedef long LONG;
typedef LONG *PLONG, *LPLONG;

typedef unsigned long ULONG;
typedef ULONG *PULONG; 

typedef unsigned long DWORD;
typedef DWORD *PDWORD, *LPDWORD;

#endif

typedef size_t SIZE_T;

#define FORCEINLINE __forceinline

#if defined(__APPLE__) || defined(__ANDROID_API__)
#define memcpy_s(Dst,Cap,Src,Count) memcpy((Dst),(Src),(Count))
#define __stdcall  // TODO: remove once RSA implementation changed to bignum
#endif

#if defined(__APPLE__)
#define __in
#define __in_bcount(x)
#define __inout_bcount(x)
#define __out_bcount_full(x)
#define UINT_MAX        0xffffffff
#endif

// From "minwindef.h"
#ifndef NOMINMAX

#ifndef max
#define max(a,b)            (((a) > (b)) ? (a) : (b))
#endif

#ifndef min
#define min(a,b)            (((a) < (b)) ? (a) : (b))
#endif

#endif  /* NOMINMAX */

// NTSTATUS from platform.h
#if defined(NT_BUILD)

#if defined(RSA32_INCLUDE_NT)
  #include <nt.h>
  #include <ntrtl.h>
  #include <nturtl.h>
#endif //defined(RSA32_INCLUDE_NT)

#else

typedef LONG NTSTATUS;

//
// define status codes not defined downlevel....
//

#if !defined(STATUS_SUCCESS)
#define STATUS_SUCCESS                   ((DWORD   )0x00000000L)
#define STATUS_AUTH_TAG_MISMATCH         ((DWORD   )0xC000A002L)
#define STATUS_INVALID_PARAMETER         ((DWORD   )0xC000000DL)
#endif

#endif /*NT_BUILD*/


#include <limits.h>

#endif // __PORT_H__
