#pragma once
#include <iostream>
#include <windows.h>
#include <tchar.h>
#include <winternl.h>


#define EXIT_WITH_ERROR( e ) { fprintf(stderr,"*** %s Error=%d  *** \n", e, GetLastError() ); return(2); }

using NtUnmapViewOfSection = NTSTATUS(WINAPI*)(HANDLE, PVOID);

#pragma comment(lib,"ntdll.lib")
EXTERN_C NTSTATUS NTAPI NtTerminateProcess(HANDLE, NTSTATUS);

typedef struct _PAYLOADFILE {
	HANDLE hpayloadFile;
	HANDLE hmapFile;
	DWORD  payloadSize;
	LPVOID lpBuffer;
} PAYLOADFILE, * PPAYLOADFILE;

int _CreateProcess(LPCWSTR targetPath, LPCWSTR sourcePath);
int ReadPayload(LPCWSTR sourcePath, PPAYLOADFILE pFile);
int UnMapAndInject(LPPROCESS_INFORMATION pPi, PVOID buffer, DWORD sizeBuffer);