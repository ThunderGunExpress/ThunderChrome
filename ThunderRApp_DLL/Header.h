#ifndef HEADER_H_
#define HEADER_H_

#include <string>
#include <iostream>
#include <codecvt>
#include <Windows.h>
#include <TlHelp32.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <Shlwapi.h>
#pragma comment(lib, "Version.lib")
#pragma comment(lib, "Shlwapi.lib")

using namespace std;

//ServiceManagement.cpp
BOOL __stdcall StopDependentServices();
VOID __stdcall DoStartSvc(LPCSTR szSvcName);
VOID __stdcall DoStopSvc(LPCSTR szSvcName);

//Impersonate_TrustedInstaller.cpp
//https://github.com/lilkui/runasti
void enable_privilege(string privilege_name);
DWORD get_process_id_by_name(const string process_name);
void impersonate_system();
int start_trusted_installer_service();
bool impersonate_trusted_installer(const DWORD pid);

//Thunder_RApp.cpp
const DWORD dwBuffsize = 256;
//Get File Version - Used for ntoskrnl.exe and termsrv.dll
bool VGetFileVersion(const char *cTargetFileVer, bool bIsNTOSKrnl);
//Grab SYSTEM32 for those D:\ systems
void VGetSystem32Path();
//Move TrustedInstaller File
bool BMoveTIFile(const wchar_t wcTargetFilePath[dwBuffsize], const wchar_t wcBackupFilePath[dwBuffsize]);
//Switch the termsrv.dll version and set the original and modified hex strings
bool BOSSwitchCheck();
//Patch the file
bool BPatchTermSrv(wchar_t wcBackupFilePath[], wchar_t wcTargetFilePath[]);
//Entry point for patching
bool BPatchStart();
//Entry point for reverting
bool BRevertStart();
//Hex replacement function
size_t IReplaceHex(FILE *fi, FILE *fo, uint8_t *what, uint8_t *repl, size_t size);
//All purpose structure
struct stTargetSystem
{
	int iOSReleaseVersion;
	int iOSReleaseSP;
	int iOSBuildVersion;
	int iOSMinorBuildVersion;
	int iTSReleaseVersion;
	int iTSReleaseSP;
	int iTSBuildVersion;
	int iTSMinorBuildVersion;
	wchar_t wcSystem32Path[dwBuffsize];
	DWORD dwTIProcess;
	uint8_t uiOriginalTermSrv[12] = {};
	uint8_t uiChangedTermSrv[12] = {};
};
extern stTargetSystem stTarget;

#endif