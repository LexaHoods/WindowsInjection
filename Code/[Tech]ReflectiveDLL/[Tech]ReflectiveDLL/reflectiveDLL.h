#pragma once

#include <vector>
#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>

#define EXIT_WITH_ERROR( e ) { fprintf(stderr,"*** %s Error=%d  *** \n", e, GetLastError() ); exit(-1); }

//function prototypes 
typedef HMODULE	(__stdcall* pLoadLibraryA)(LPCSTR);
typedef FARPROC	(__stdcall* pGetProcAddress)(HMODULE, LPCSTR);
typedef INT		(__stdcall* dllmain)(HMODULE, DWORD, LPVOID);

std::wstring stringToWString(const std::string& s);
DWORD processID(const std::string name);
DWORD __stdcall manualLoader(LPVOID Memory);
DWORD __stdcall stub();

// Manual mapping Data structure
struct loaderData
{
	pLoadLibraryA f_LoadLibraryA;
	pGetProcAddress f_GetProcAddress;

	LPVOID imageBase;
	PIMAGE_NT_HEADERS ntHeaders;
	PIMAGE_BASE_RELOCATION baseReloc;
	PIMAGE_IMPORT_DESCRIPTOR importDirectory;

};