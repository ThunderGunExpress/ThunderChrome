/* dllmain.cpp : Defines the entry point for the DLL application.
* Compiled with Visual Studio 2017
* x64 Reflective DLL
* Character Set - Use Multi-Byte Character Set
* PreProcessor Defs:
* _CRT_SECURE_NO_WARNINGS;WIN64;WIN_X64;NDEBUG;_WINDOWS;_USRDLL;RDLL_EXPORTS;REFLECTIVE_DLL_EXPORTS;REFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR;REFLECTIVEDLLINJECTION_CUSTOM_DLLMAIN
* Runtime Library: Multi-Threaded (/MT)
*
* Termsrv.dll versions this currently can detect and modify
* 10.0.17134.1
* 10.0.16299.15
* 10.0.15063.0
* 10.0.15063.1155
* 10.0.10586.0
* 10.0.10240.16384
*
* *************References**************
* Run Programs as Trusted Installer
* https://github.com/lilkui/runasti
* Service Management
* https://docs.microsoft.com/en-us/windows/desktop/services/stopping-a-service
* Grabbing File Versions (used for ntskrnl.exe and termsrv.dll)
* https://helloacm.com/c-function-to-get-file-version-using-win32-api-ansi-and-unicode-version/
* https://stackoverflow.com/questions/940707/how-do-i-programmatically-get-the-version-of-a-dll-or-exe-file
* Termsrv.dll Patch Strings
* https://www.mysysadmintips.com/windows/clients/545-multiple-rdp-remote-desktop-sessions-in-windows-10
* Find and Replace Hex
* https://stackoverflow.com/questions/21189683/find-and-replace-hex
*/

#include "ReflectiveLoader.h"
#include "Header.h"

struct stTargetSystem stTarget;

extern "C" HINSTANCE hAppInstance;
BOOL APIENTRY DllMain( HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved )
{
	bool bReturnValue = FALSE;
	switch (ul_reason_for_call)
	{
	case DLL_QUERY_HMODULE:
		if (lpReserved != NULL)
		{
			*(HMODULE *)lpReserved = hAppInstance;
		}
		break;
	case DLL_PROCESS_ATTACH:
		printf("\r\n==========Running ThunderRApp==========");
		hAppInstance = hModule;
		if (lpReserved != NULL)
		{
			printf("\r\nParameter passed to Reflective DLL: %s.", (char *)lpReserved);
			if (!strcmp((char*)lpReserved, "--patch"))
			{
				printf("\r\nAttempting to patch termsrv.dll");
				bReturnValue = BPatchStart();
			}
			else if (!strcmp((char*)lpReserved, "--revert"))
			{
				printf("\r\nAttempting to revert termsrv.dll");
				bReturnValue = BRevertStart();
			}
			else
			{
				printf("\r\nParameter issue.");
				bReturnValue = FALSE;
			}
		}
		else
		{
			printf("\r\nNo parameter passed to Reflective DLL.");
			bReturnValue = FALSE;
		}

		if (bReturnValue == TRUE)
			printf("\r\nLooks like everything ran okay.");
		else
			printf("\r\nLooks like something went wrong");	
		fflush(stdout);
		ExitProcess(0);
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

