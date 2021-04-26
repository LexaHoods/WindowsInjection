// dllmain.cpp : Définit le point d'entrée de l'application DLL.
#include "pch.h"
#include <Windows.h>

extern "C" void __declspec(dllexport) Show() {
    
    MessageBox(NULL, L"Hello, You have Pwned ! I'm evil dll", L"EvIlDLL", MB_OK);

}


BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Show, NULL, 0, NULL);
    }
    return TRUE;
}