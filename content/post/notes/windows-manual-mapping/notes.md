---
title: "Windows manual mapping"
date: 2020-12-25T22:44:00+08:00
draft: false
---

# Introduction

After going through the first 3 chapters of Windows internals, I am getting a little bored with all the theory stuff. So I decided to do something more hands on for a change. The theory covered by the first 3 chapters of Windows internals gave me a grasp of how windows works with executables and DLLs. Now I would like to try to write a module that allows me to load a DLL from memory manually instead of using the API LoadLibrary. This is because LoadLibrary only works with files on disk and sometimes this is not necessary.

This is a well documented technique used in both malwares and gamecheats so it will be fun to explore how they work under the hood. The potential use of this could be receiving an encrypted DLL file from the network and decrypt it in the application and load it without touching the disk.

# Manual Mapping

## Applications

Manual Mapping is a technique that is used to avoid detection from anti cheat software. This technique is about emulating the important steps of LoadLibrary without updating the EPROCESS kernel data structure. By injecting a DLL into another process without using LoadLibrary API call and the module will not be listed by reading the EPROCESS data structure, this DLL will be effectively hidden from anti cheat software unless it is enumerating all mapped memory regions in the game process.

Similarly, this technique can be used by malwares to make an application looks benign until something triggers the loading routine by fetching a web resource and mapping the malicious DLL into its own process. Unless an antivirus is scanning the full memory region of every running process, it is difficult to detect as the original file does not contain any malicious code until something triggers the loading routine.

## How it works

Enough talking about the possible ways to apply this technique, now we dive into the details on how to make it work. In this post I will be injecting a DLL into my own application process like what a malware will do. Injecting DLL into another process like game cheats requires additional step of opening a process handle to the remote process and writing to that memory. It is not very difficult and I will leave a link to a guided tutorial on how to do that.

### Sample DLL

For a minimal DLL, just need to define a DllMain function.

```C++
#include "pch.h"

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        puts("hello from memory");
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
```

### Sample main application

For ease of use I will load the DLL from file. In actual case as long the DLL is loaded into memory through some means, could be network or decryption or hardcoded, it should work

```c++
#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>
#include "manualMap.h"

UINT64 getFileSize(const char* path) {
	FILE* fp;
	fopen_s(&fp, path, "rb");
	if (!fp) {
		puts("File opening failed");
		return 0;
	}

	fseek(fp, 0, SEEK_END);
	UINT64 fSize = ftell(fp);

	fclose(fp);
	return fSize;
}

UINT64 loadFile(const char* path, BYTE* buf) {
	FILE* fp;
	fopen_s(&fp, path, "rb");
	if (!fp) {
		puts("File opening failed");
		return 0;
	}

	fseek(fp, 0, SEEK_END);
	UINT64 fSize = ftell(fp);
	rewind(fp);

	UINT64 result = fread(buf, 1, fSize, fp);

	if (result != fSize) {
		puts("Reading error");
		return 0;
	}

	fclose(fp);
	return result;
}

int main(int argc, const char** argv) {
	puts("hello world");


	auto fileSize = getFileSize(argv[1]);
	BYTE* DllFile = static_cast<BYTE*>(malloc(fileSize));
	if (!loadFile(argv[1], DllFile)) {
		puts("failed to read file");
		free(DllFile);
		return 1;
	}
	ManualMap(DllFile, fileSize);
	free(DllFile);
	return 0;
}
```

### Manual Mapper

This is where the bulk of the operations happen. It will emulate the LoadLibrary Process.

The very first thing the mapper will do is to check if the DLL file is valid.

```c++
#define GET_NT_HEADER(pBase) reinterpret_cast<PIMAGE_NT_HEADERS>(pBase + reinterpret_cast<PIMAGE_DOS_HEADER>(pBase)->e_lfanew)
bool isValidDll(BYTE* DllFile, UINT size) {
	// first 0x1000 bytes are reserved for PE header. so if file smaller than 0x1000, it
	// cannot be a valid PE file
	if (size < 0x1000) {
		puts("DLL too small to be valid");
		return false;
	}

	// check magic header
	if (reinterpret_cast<PIMAGE_DOS_HEADER>(DllFile)->e_magic != 0x5A4D) {
		puts("DLL not a PE file");
		return false;
	}


	// check architecture
#ifdef _WIN64
#define VALID_MACHINE IMAGE_FILE_MACHINE_AMD64
#else
#define VALID_MACHINE IMAGE_FILE_MACHINE_I386
#endif
	PIMAGE_NT_HEADERS ntHeader = GET_NT_HEADER(DllFile);
	if (ntHeader->FileHeader.Machine != VALID_MACHINE) {
		puts("Invalid platform");
		return false;
	}
    return true;
}
```

Then, we will allocate a memory region for the DLL to be loaded. Windows DLL achieve position independent code using a technique called relocations. At compile time, DLL's includes a preferred base address in the PE header. If the DLL can be mapped to the preferred base address, no relocation is necessary and it can be used immediately. If it is not mapped to the preferred base address, an additional step of relocation is necessary. It is basically patching the PE file's absolute addresses using a relocation table stored in a PE section. But first thing first, we need  to allocate a memory region in our running process.

```C++
	// Store the useful header pointers
	PIMAGE_NT_HEADERS		pNtHeader   = GET_NT_HEADER(DllFile);
	PIMAGE_OPTIONAL_HEADER  pOptHeader  = &pNtHeader->OptionalHeader;
	PIMAGE_FILE_HEADER		pFileHeader = &pNtHeader->FileHeader;
	
	// Create a memory region in current process
	BYTE* pTargetBase = (BYTE*)VirtualAlloc(
						reinterpret_cast<LPVOID>(pOptHeader->ImageBase),
						pOptHeader->SizeOfImage,
						MEM_COMMIT | MEM_RESERVE,
						PAGE_EXECUTE_READWRITE
						);
	if (!pTargetBase) {
		pTargetBase = (BYTE*)VirtualAlloc(
						nullptr,
						pOptHeader->SizeOfImage,
						MEM_COMMIT | MEM_RESERVE,
						PAGE_EXECUTE_READWRITE
						);
		if (!pTargetBase) {
			printf("pTargetBase memory allocation fail 0x%X\n", GetLastError());
			return false;
		}
	}
```

Then we need to map all the sections from the DLL file to our memory at appropriate positions.

```c++
void mapSections(BYTE* pTargetBase, BYTE* dllBase, UINT numSections) {
	auto* dllSectionHeader = IMAGE_FIRST_SECTION(GET_NT_HEADER(dllBase));
	for (UINT i = 0; i != numSections; i++, dllSectionHeader++) {
		printf("mapping %s section to RVA 0x%X\n", dllSectionHeader->Name, dllSectionHeader->VirtualAddress);
		memcpy(pTargetBase + dllSectionHeader->VirtualAddress, dllBase + dllSectionHeader->PointerToRawData, dllSectionHeader->SizeOfRawData);
	}
}
```

After mapping, we need to start relocating. The code should be rather self explanatory on how the relocation is done. The general idea is that there is an array of relocation blocks (`pRelocData`). Each block has a virtual address and an array of offsets. Then just need to patch each `block->VirtualAddress + offset` with the delta value.

```c++
void relocateDll(BYTE* pTargetBase, PIMAGE_OPTIONAL_HEADER pOptHeader) {
#define RELOC_PLATFORM_ISVALID32(type) (type == IMAGE_REL_BASED_HIGHLOW)
#define RELOC_PLATFORM_ISVALID64(type) (type == IMAGE_REL_BASED_DIR64)

#ifdef _WIN64
#define RELOC_PLATFORM_ISVALID(type) RELOC_PLATFORM_ISVALID64(type)
#else
#define RELOC_PLATFORM_ISVALID(type) RELOC_PLATFORM_ISVALID32(type)
#endif

	ptrdiff_t relocDelta = reinterpret_cast<ptrdiff_t>(pTargetBase - pOptHeader->ImageBase);

	if (!relocDelta) {
		return;
	}

	if (!pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
		return;
	}

	auto pRelocData = reinterpret_cast<PIMAGE_BASE_RELOCATION>(pTargetBase + pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	while (pRelocData->VirtualAddress) {
		// size of IMAGE_BASE_RELOCATION struct is 8, it is followed by array of WORD containing all the offsets
		UINT numEntries = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION) / sizeof(WORD));
		WORD* TypeOffset = reinterpret_cast<WORD*>(pRelocData + 1);
		for (;numEntries--; TypeOffset++) {
			UINT type   = *TypeOffset >> 12;
			UINT offset = *TypeOffset & 0xfff;
			if (RELOC_PLATFORM_ISVALID(type)) {
				UINT_PTR* patchAddr = reinterpret_cast<UINT_PTR*>(pTargetBase + pRelocData->VirtualAddress + offset);
				*patchAddr += relocDelta;
			}
		}

		// next relocdata block
		pRelocData = reinterpret_cast<PIMAGE_BASE_RELOCATION>(offsetPtr(pRelocData, pRelocData->SizeOfBlock));
	}
}
```

After relocations, we need to fix the import tables of the target DLL as well. It should contain mostly system DLLs. To save ourselves some trouble, we will use the WINAPI LoadLibrary for those DLLs. Since they are the DLL we are trying to hide, it doesn't really matter if it shows up in DLL list for our process. Fixing IAT basically involves loading every DLL that our DLL demands and then filling the function thunk with addresses.

```C++
bool fixIAT(BYTE* pTargetBase, PIMAGE_OPTIONAL_HEADER pOptHeader) {
	if (!pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) { return; }
	
	auto pImportDesc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(pTargetBase + pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	while (pImportDesc->Name) {
		char* szMod = reinterpret_cast<char*>(pTargetBase + pImportDesc->Name);
		printf("Loading %s\n", szMod);

		HINSTANCE hDll = LoadLibrary(szMod);
		if (!hDll) {
			puts("load IAT library failed");
			return false;
		}
		UINT_PTR* pThunkRef = reinterpret_cast<UINT_PTR*>(pTargetBase + pImportDesc->OriginalFirstThunk);
		FARPROC* pFuncRef = reinterpret_cast<FARPROC*>(pTargetBase + pImportDesc->FirstThunk);
		if (!pThunkRef) { pThunkRef = reinterpret_cast<UINT_PTR*>(pFuncRef); }
		for (; *pThunkRef; ++pThunkRef, ++pFuncRef) {
			if (IMAGE_SNAP_BY_ORDINAL(*pThunkRef)) {
				*pFuncRef = GetProcAddress(hDll, reinterpret_cast<const char*>(IMAGE_ORDINAL(*pThunkRef)));
			}
			else {
				auto* thunkData = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(pTargetBase + (*pThunkRef));
				*pFuncRef = GetProcAddress(hDll, thunkData->Name);
			}
		}
		++pImportDesc;
	}
	return true;
}
```

Lastly, we need to run the TLS callbacks.

```C++
void TlsRun(BYTE* pTargetBase, PIMAGE_OPTIONAL_HEADER pOptHeader) {
	if (!pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) { return; }
	auto pTls = reinterpret_cast<PIMAGE_TLS_DIRECTORY>(pTargetBase + pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
	auto pCallBack = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pTls->AddressOfCallBacks);
	if (pCallBack) {
		for (;*pCallBack; pCallBack++) {
			(*pCallBack)(reinterpret_cast<void*>(pTargetBase), DLL_PROCESS_ATTACH, nullptr);
		}
	}
}
```

Our main function manual mapper is as follows

```c++
bool ManualMap(BYTE* DllFile, UINT fSize) {
	// check if file is valid
	if (!isValidDll(DllFile, fSize)) {
		puts("DLL not valid");
		return false;
	}

	// Store the useful header pointers
	PIMAGE_NT_HEADERS		pNtHeader   = GET_NT_HEADER(DllFile);
	PIMAGE_OPTIONAL_HEADER  pOptHeader  = &pNtHeader->OptionalHeader;
	PIMAGE_FILE_HEADER		pFileHeader = &pNtHeader->FileHeader;

	// Create a memory region in current process
	 BYTE* pTargetBase = reinterpret_cast<BYTE*>(VirtualAlloc(
						reinterpret_cast<LPVOID>(pOptHeader->ImageBase),
						pOptHeader->SizeOfImage,
						MEM_COMMIT | MEM_RESERVE,
						PAGE_EXECUTE_READWRITE
						));
	if (!pTargetBase) {
		pTargetBase = reinterpret_cast<BYTE*>(VirtualAlloc(
					  nullptr,
					  pOptHeader->SizeOfImage,
					  MEM_COMMIT | MEM_RESERVE,
					  PAGE_EXECUTE_READWRITE
					  ));
		if (!pTargetBase) {
			printf("pTargetBase memory allocation fail 0x%X\n", GetLastError());
			return false;
		}
	}

	mapSections(pTargetBase, DllFile, pFileHeader->NumberOfSections);
	if (pTargetBase != (BYTE*)pOptHeader->ImageBase) {
		relocateDll(pTargetBase, pOptHeader);
	}
	if (!fixIAT(pTargetBase, pOptHeader)) {
		puts("failed to fix IAT");
		VirtualFree(pTargetBase, 0, MEM_RELEASE);
		return false;
	}

	TlsRun(pTargetBase, pOptHeader);

	auto _DllMain = reinterpret_cast<f_DLL_ENTRY_POINT>(pTargetBase + pOptHeader->AddressOfEntryPoint);
	_DllMain(reinterpret_cast<void*>(pTargetBase), DLL_PROCESS_ATTACH, nullptr);

    // unloading the dll, if you are using the DLL for dllmain only, for covert purposes
	VirtualFree(pTargetBase, 0, MEM_RELEASE);
	return true;
}
```

# Conclusion

This is an interesting side project I decided to work on. From copying chunks of code from online resources to understanding the process and restructuring the code, I have gained a much better understanding of how DLL loading and relocation works on Windows. Windows is packing a lot of information in the headers and using sections to store data for its linkers.

I have uploaded the VS2019 solution on my own [github](https://github.com/rootkie/Windows-manual-mapping).

# References

Most of the code presented here are referenced from memory module ([github](https://github.com/fancycode/MemoryModule)) and the guided hacking [youtube series](https://www.youtube.com/watch?v=qzZTXcBu3cE). The memory module is meant for loading code in our own process while guided hacking series one is meant for injecting the DLL into another process.
