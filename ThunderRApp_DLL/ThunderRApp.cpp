// ThunderRApp_1.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include "Header.h"

//Grab file version. Used to fingerprint termsrv.dll
bool VGetFileVersion(const char *cTargetFileVer, bool bIsNTOSKrnl)
{
	DWORD dwHandle = 0;
	UINT uisize = 0;
	LPBYTE lpBuffer = NULL;
	DWORD sz = GetFileVersionInfoSizeA(cTargetFileVer, &dwHandle);
	if (sz == 0)
	{
		printf("\r\nGetFileVersion: Unable to find %s", cTargetFileVer);
		return false;
	}
	LPSTR buf = new char[sz];
	if (!GetFileVersionInfoA(cTargetFileVer, dwHandle, sz, buf))
	{
		delete buf;
		printf("\r\nGetFileVersion: Unable to get %s version info", cTargetFileVer);
		return false;
	}
	VS_FIXEDFILEINFO * pvi = NULL;
	sz = sizeof(VS_FIXEDFILEINFO);
	if (!VerQueryValueA(&buf[0], "\\", (LPVOID*)&pvi, (unsigned int*)&sz))
	{
		delete buf;
		printf("\r\nGetFileVersion: Unable to query %s version info", cTargetFileVer);
		return false;
	}
	//Sorry :(
	if (bIsNTOSKrnl == true)
	{
		stTarget.iOSReleaseVersion = (pvi->dwProductVersionMS >> 16) & 0xFFFF;
		stTarget.iOSReleaseSP = (pvi->dwFileVersionMS >> 0) & 0xFFFF;
		stTarget.iOSBuildVersion = (pvi->dwFileVersionLS >> 16) & 0xFFFF;
		stTarget.iOSMinorBuildVersion = (pvi->dwFileVersionLS >> 0) & 0xFFFF;
	}
	else
	{
		stTarget.iTSReleaseVersion = (pvi->dwProductVersionMS >> 16) & 0xFFFF;
		stTarget.iTSReleaseSP = (pvi->dwFileVersionMS >> 0) & 0xFFFF;
		stTarget.iTSBuildVersion = (pvi->dwFileVersionLS >> 16) & 0xFFFF;
		stTarget.iTSMinorBuildVersion = (pvi->dwFileVersionLS >> 0) & 0xFFFF;
	}
	delete buf;
	return true;
}

//Dynamically grab SYSTEM32. For you D:\ weirdos :)
void VGetSystem32Path()
{
	PVOID pvOldValue = NULL;
	if (Wow64DisableWow64FsRedirection(&pvOldValue))
	{
		GetEnvironmentVariableW(L"WINDIR", stTarget.wcSystem32Path, dwBuffsize);
		wcscat_s(stTarget.wcSystem32Path, dwBuffsize, L"\\system32\\");
	}
	else
	{
		GetEnvironmentVariableW(L"WINDIR", stTarget.wcSystem32Path, dwBuffsize);
		wcscat_s(stTarget.wcSystem32Path, dwBuffsize, L"\\system32\\");
	}
}

//Move a file after we've impersonated TI
bool BMoveTIFile(const wchar_t wcTargetFilePath[dwBuffsize], const wchar_t wcBackupFilePath[dwBuffsize])
{
	wprintf(L"\r\nAttempting to move file %ls to %ls", wcTargetFilePath, wcBackupFilePath);
	//Check if termsrv.dll.backup exists
	if (PathFileExistsW(wcBackupFilePath))
	{
		wprintf(L"\r\nFile %ls already exists. Exiting.", wcBackupFilePath);
		return false;
	}

	//Perform the file copy
	if (!MoveFileW(wcTargetFilePath, wcBackupFilePath))
	{
		printf("\r\nMoveFileW failed. Exiting.");
		return false;
	}
	return true;
}

//Sorry for this, so janky.
//Switch the termsrv.dll version and fill the search and replace hex strings
//Termsrv.dll versions included
//10.0.17134.1
//10.0.16299.15
//10.0.15063.0
//10.0.15063.1155
//10.0.10586.0
//10.0.10240.16384
bool BOSSwitchCheck()
{
	switch (stTarget.iTSReleaseVersion)
	{
	case 10:
		switch (stTarget.iTSReleaseSP)
		{
		case 0:
			switch (stTarget.iTSBuildVersion)
			{
			case 17134:
				//10.0.17134.1
				if (stTarget.iTSMinorBuildVersion == 1)
				{
					uint8_t uiOriginalTermSrv[] = { 0x8B, 0x99, 0x3C, 0x06, 0x00, 0x00, 0x8B, 0xB9, 0x38, 0x06, 0x00, 0x00 };
					uint8_t uiChangedTermSrv[] =  { 0xB8, 0x00, 0x01, 0x00, 0x00, 0x89, 0x81, 0x38, 0x06, 0x00, 0x00, 0x90 };

					std::copy(std::begin(uiOriginalTermSrv), std::end(uiOriginalTermSrv), std::begin(stTarget.uiOriginalTermSrv));
					std::copy(std::begin(uiChangedTermSrv), std::end(uiChangedTermSrv), std::begin(stTarget.uiChangedTermSrv));
					printf("\r\nTermsrv.dll switch statement passed.");
					return true;
				}
				else
				{
					printf("\r\nTermsrv.dll switch statement failed.");
					return false;
				}
				break;
			case 16299:
				//10.0.16299.15
				if (stTarget.iTSMinorBuildVersion == 15)
				{
													//39    81    3C    06    00    00    0F    84    B1    7D    02    00
					uint8_t uiOriginalTermSrv[] = { 0x39, 0x81, 0x3C, 0x06, 0x00, 0x00, 0x0F, 0x84, 0xB1, 0x7D, 0x02, 0x00 };
					uint8_t uiChangedTermSrv[] =  { 0xB8, 0x00, 0x01, 0x00, 0x00, 0x89, 0x81, 0x38, 0x06, 0x00, 0x00, 0x90 };

					std::copy(std::begin(uiOriginalTermSrv), std::end(uiOriginalTermSrv), std::begin(stTarget.uiOriginalTermSrv));
					std::copy(std::begin(uiChangedTermSrv), std::end(uiChangedTermSrv), std::begin(stTarget.uiChangedTermSrv));
					printf("\r\nTermsrv.dll switch statement passed.");
					return true;
				}
				else
				{
					printf("\r\nTermsrv.dll switch statement failed.");
					return false;
				}
				break;
			case 15063:
				//10.0.15063.0
				if (stTarget.iTSMinorBuildVersion == 0)
				{
													//39    81    3C    06    00    00    0F    84    53    71    02    00
					uint8_t uiOriginalTermSrv[] = { 0x39, 0x81, 0x3C, 0x06, 0x00, 0x00, 0x0F, 0x84, 0x53, 0x71, 0x02, 0x00 };
					uint8_t uiChangedTermSrv[] =  { 0xB8, 0x00, 0x01, 0x00, 0x00, 0x89, 0x81, 0x38, 0x06, 0x00, 0x00, 0x90 };

					std::copy(std::begin(uiOriginalTermSrv), std::end(uiOriginalTermSrv), std::begin(stTarget.uiOriginalTermSrv));
					std::copy(std::begin(uiChangedTermSrv), std::end(uiChangedTermSrv), std::begin(stTarget.uiChangedTermSrv));
					printf("\r\nTermsrv.dll switch statement passed.");
					return true;
				}
				//10.0.15063.1155
				if (stTarget.iTSMinorBuildVersion == 1155)
				{
													//39    81    3C    06    00    00    0F    84    E5    58    02    00
					uint8_t uiOriginalTermSrv[] = { 0x39, 0x81, 0x3C, 0x06, 0x00, 0x00, 0x0F, 0x84, 0xE5, 0x58, 0x02, 0x00 };
					uint8_t uiChangedTermSrv[] =  { 0xB8, 0x00, 0x01, 0x00, 0x00, 0x89, 0x81, 0x38, 0x06, 0x00, 0x00, 0x90 };

					std::copy(std::begin(uiOriginalTermSrv), std::end(uiOriginalTermSrv), std::begin(stTarget.uiOriginalTermSrv));
					std::copy(std::begin(uiChangedTermSrv), std::end(uiChangedTermSrv), std::begin(stTarget.uiChangedTermSrv));
					printf("\r\nTermsrv.dll switch statement passed.");
					return true;
				}
				else
				{
					printf("\r\nTermsrv.dll switch statement failed.");
					return false;
				}
				break;
				//10.0.10586.0
			case 10586:
				if (stTarget.iTSMinorBuildVersion == 0)
				{
													//39	81	  3C	06	  00    00	  0F    84    3F    42    02    00
					uint8_t uiOriginalTermSrv[] = { 0x39, 0x81, 0x3C, 0x06, 0x00, 0x00, 0x0F, 0x84, 0x3F, 0x42, 0x02, 0x00 };
					uint8_t uiChangedTermSrv[] =  { 0xB8, 0x00, 0x01, 0x00, 0x00, 0x89, 0x81, 0x38, 0x06, 0x00, 0x00, 0x90 };

					std::copy(std::begin(uiOriginalTermSrv), std::end(uiOriginalTermSrv), std::begin(stTarget.uiOriginalTermSrv));
					std::copy(std::begin(uiChangedTermSrv), std::end(uiChangedTermSrv), std::begin(stTarget.uiChangedTermSrv));
					printf("\r\nTermsrv.dll switch statement passed.");
					return true;
				}
				else
				{
					printf("\r\nTermsrv.dll switch statement failed.");
					return false;
				}
				break;
				//10.0.10240.16384
			case 10240:
				if (stTarget.iTSMinorBuildVersion == 16384)
				{
					//								  39    81	  3C    06    00    00    0F    84    73    42    02    00
					uint8_t uiOriginalTermSrv[] = { 0x39, 0x81, 0x3C, 0x06, 0x00, 0x00, 0x0F, 0x84, 0x73, 0x42, 0x02, 0x00 };
					uint8_t uiChangedTermSrv[] =  { 0xB8, 0x00, 0x01, 0x00, 0x00, 0x89, 0x81, 0x38, 0x06, 0x00, 0x00, 0x90 };

					std::copy(std::begin(uiOriginalTermSrv), std::end(uiOriginalTermSrv), std::begin(stTarget.uiOriginalTermSrv));
					std::copy(std::begin(uiChangedTermSrv), std::end(uiChangedTermSrv), std::begin(stTarget.uiChangedTermSrv));
					printf("\r\nTermsrv.dll switch statement passed.");
					return true;
				}
				else
				{
					printf("\r\nTermsrv.dll switch statement failed.");
					return false;
				}
				break;

			default:
				printf("\r\nTermsrv.dll switch statement failed.");
				return false;
			}
			break;
		default:
			printf("\r\nTermsrv.dll switch statement failed.");
			return false;
		}
		break;
	default:
		printf("\r\nTermsrv.dll switch statement failed.");
		return false;
		break;
	}

}

//Called after termsrv.dll has been moved
//Reads file data from termsrv.dll.backup (the unmodified version)
//Writes file data to termsrv.dll which is the same except with the modified hex string
bool BPatchTermSrv(wchar_t wcBackupFilePath[], wchar_t wcTargetFilePath[])
{
	printf("\r\nPatching %ls", wcTargetFilePath);
	FILE *file, *fileout;
	size_t count;
	file = _wfopen(wcBackupFilePath, L"rb");
	if (file == NULL)
	{
		printf("\r\nError opening %ls", wcBackupFilePath);
		printf("\r\nRecommend restoring the backup %ls", wcBackupFilePath);
		return false;
	}

	fileout = _wfopen(wcTargetFilePath, L"wb");
	if (fileout == NULL)
	{
		printf("\r\nError opening %ls", wcTargetFilePath);
		printf("\r\nRecommend restoring the backup %ls", wcBackupFilePath);
		fclose(file);
	}

	count = IReplaceHex(file, fileout, stTarget.uiOriginalTermSrv, stTarget.uiChangedTermSrv, sizeof(stTarget.uiOriginalTermSrv));
	if (count == 1)
	{
		printf("\r\n%ls was patched successfully.", wcTargetFilePath);
		fclose(file);
		fclose(fileout);
		return true;
	}
	else
	{
		printf("\r\n%ls was NOT patched. Recommend restoring the backup %ls", wcTargetFilePath, wcBackupFilePath);
		fclose(file);
		fclose(fileout);
		return false;
	}
}

//Called to Find and Replace the Hex String in BOSSwitchCheck()
//https://stackoverflow.com/questions/21189683/find-and-replace-hex
size_t IReplaceHex(FILE *fi, FILE *fo, uint8_t *what, uint8_t *repl, size_t size)
{
	size_t i, index = 0, count = 0;
	int ch;
	while (EOF != (ch = fgetc(fi))) {
		if (ch == what[index]) {
			if (++index == size) {
				for (i = 0; i < size; ++i) {
					fputc(repl[i], fo);
				}
				index = 0;
				++count;
			}
		}
		else {
			for (i = 0; i < index; ++i) {
				fputc(what[i], fo);
			}
			index = 0;
			fputc(ch, fo);
		}
	}
	for (i = 0; i < index; ++i) {
		fputc(what[i], fo);
	}

	return count;
}

//Main Kickoff Function
bool BPatchStart()
{

	//We'll dynamically grab the system32 later
	char cNTKernPath[] = "C:\\windows\\system32\\ntoskrnl.exe";
	char cTermsrvPath[] = "C:\\windows\\system32\\termsrv.dll";
	HKEY key;
	DWORD dwFDisabledAllowList;
	DWORD dwType = REG_DWORD;
	DWORD dwSize = 255;
	DWORD dwFDisabledAllowListSet = 1;

	//Grab file version of ntoskrnl.exe for the OS version
	if (!VGetFileVersion(cNTKernPath, true))
	{
		printf("\r\nError finding %s. Quitting.", cNTKernPath);
		return false;
	}

	//Grab file version of termsrv.dll to use in the switch statement
	if (!VGetFileVersion(cTermsrvPath, false))
	{
		printf("\r\nError finding %s. Quitting.", cTermsrvPath);
		return false;
	}

	//Grab the SYSTEM32 path. I know we hardcode it above :S ... PoC code
	VGetSystem32Path();

	wchar_t wcTargetFilePath[dwBuffsize];
	wchar_t wcBackupFilePath[dwBuffsize];

	//Initializing File Paths
	wcscpy_s(wcTargetFilePath, dwBuffsize, stTarget.wcSystem32Path);
	wcscpy_s(wcBackupFilePath, dwBuffsize, stTarget.wcSystem32Path);
	//Write Path - SYSTEM32\termsrv.dll ... this will be your modified version, if it completes correctly
	wcscat_s(wcTargetFilePath, dwBuffsize, L"termsrv.dll");
	//Backup Path - SYSTEM32\termsrv.dll.backup ... this is your unmodified backup version
	wcscat_s(wcBackupFilePath, dwBuffsize, L"termsrv.dll.backup");

	//Print System Info
	printf("\r\n\r\n==============System Info==============");
	printf("\r\nOS Version: %d.%d.%d.%d", stTarget.iOSReleaseVersion, stTarget.iOSReleaseSP, stTarget.iOSBuildVersion, stTarget.iOSMinorBuildVersion);
	printf("\r\nTermsrv.dll Version: %d.%d.%d.%d", stTarget.iTSReleaseVersion, stTarget.iTSReleaseSP, stTarget.iTSBuildVersion, stTarget.iTSMinorBuildVersion);
	printf("\r\nSystem32 Path: %ls", stTarget.wcSystem32Path);

	//Termsrv.dll version switch statement ... very important
	printf("\r\n\r\n=============Sanity Checks=============");
	//Probably a better way of doing this. Sorry.
	if (!BOSSwitchCheck())
		return false;

	//SYSTEM32 file belong to Trusted Installer, so we need to impersonate.
	printf("\r\n\r\n===========Impersonating TI============");
	printf("\r\nStarting Trusted Installer service.");
	if (!start_trusted_installer_service())
		return false;
	printf("\r\nTrusted Installer service PID: %d.", stTarget.dwTIProcess);
	printf("\r\nAttempting Trusted Installer impersonation.");
	if (!impersonate_trusted_installer(stTarget.dwTIProcess))
		return false;

	//Stopping Termservice to get at termsrv.dll
	printf("\r\n\r\n=====Stopping TermService Service======");
	DoStopSvc("TermService");

	//Backing up the unmodified termsrv.dll to termsrv.dll.backup
	printf("\r\n==========Moving Termsrv.dll===========");
	printf("\r\nSrc Path: %ls", wcTargetFilePath);
	printf("\r\nDst Path: %ls", wcBackupFilePath);
	if (!BMoveTIFile(wcTargetFilePath, wcBackupFilePath))
		return false;

	//Writing the modified termsrv.dll to termsrv.dll
	printf("\r\n\r\n=========Patching Termsrv.dll==========");
	printf("\r\nThis tool will copy and patch the src to dst.");
	printf("\r\nSrc file: %ls", wcBackupFilePath);
	printf("\r\nDst file: %ls", wcTargetFilePath);
	printf("\r\nThe src file will remain as a backup.");
	if (!BPatchTermSrv(wcBackupFilePath, wcTargetFilePath))
		return false;

	//We also need to modify registry. According to my notes this will only work on x64 bit machines.
	//Will need some TLC to get it working on x86 but honestly I never tested it ... IIRC it's something to do with WOW64 registry, definitely fixable
	//HKLM\Microsoft\Windows NT\CurrentVersion\TerminalServer\TSAppAllowList\fDisabledAllowList -> 1
	printf("\r\n\r\n=====Registry fDisabledAllowList=======");
	printf("\r\nSetting Terminal Server\\TSAppAllowList\\fDisabledAllowList to 1.");
	printf("\r\nThis will only work on x64. You lazy slob.");
	if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, TEXT("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Terminal Server\\TSAppAllowList"), 0, KEY_ALL_ACCESS | KEY_WOW64_64KEY, &key) != ERROR_SUCCESS)
	{
		printf("\r\nUnable to find TSAppAllowList");
		return false;
	}
	if (RegQueryValueEx(key, TEXT("fDisabledAllowList"), NULL, &dwType, (LPBYTE)&dwFDisabledAllowList, &dwSize) != ERROR_SUCCESS)
	{
		printf("\r\nUnable to find fDisabledAllowList");
		return false;
	}
	printf("\r\nfDisabledAllowList Value: %ld", dwFDisabledAllowList);
	if (dwFDisabledAllowList == 0)
	{
		if (RegSetValueEx(key, TEXT("fDisabledAllowList"), NULL, dwType, (LPBYTE)&dwFDisabledAllowListSet, dwSize) != ERROR_SUCCESS)
		{
			printf("\r\nUnable to set fDisabledAllowList to 1");
			return false;
		}
		if (RegQueryValueEx(key, TEXT("fDisabledAllowList"), NULL, &dwType, (LPBYTE)&dwFDisabledAllowList, &dwSize) != ERROR_SUCCESS)
		{
			printf("\r\nUnable to find fDisabledAllowList");
			return false;
		}
		printf("\r\nfDisabledAllowList Value: %ld", dwFDisabledAllowList);
	}
	printf("\r\n\r\n=====Starting TermService Service======");
	DoStartSvc("TermService");
	return true;
}

//Main Reversion Kickoff Function
bool BRevertStart()
{
	//We don't use this because because we're not switching the termsrv.dll version
	//1. deleting termsrv.dll
	//2. moving termsrv.dll.backup to termsrv.dll
	//3. Other clean up
	//char cNTKernPath[] = "C:\\windows\\system32\\ntoskrnl.exe";
	//char cTermsrvPath[] = "C:\\windows\\system32\\termsrv.dll";

	HKEY key;
	DWORD dwFDisabledAllowList;
	DWORD dwType = REG_DWORD;
	DWORD dwSize = 255;
	DWORD dwFDisabledAllowListSet = 0;

	VGetSystem32Path();
	wchar_t wcTargetFilePath[dwBuffsize];
	wchar_t wcBackupFilePath[dwBuffsize];

	wcscpy_s(wcTargetFilePath, dwBuffsize, stTarget.wcSystem32Path);
	wcscpy_s(wcBackupFilePath, dwBuffsize, stTarget.wcSystem32Path);
	wcscat_s(wcTargetFilePath, dwBuffsize, L"termsrv.dll");
	wcscat_s(wcBackupFilePath, dwBuffsize, L"termsrv.dll.backup");
	
	printf("\r\n\r\n===========Impersonating TI============");
	printf("\r\nStarting Trusted Installer service.");
	if (!start_trusted_installer_service())
		return false;
	printf("\r\nTrusted Installer service PID: %d.", stTarget.dwTIProcess);
	printf("\r\nAttempting Trusted Installer impersonation.");
	if (!impersonate_trusted_installer(stTarget.dwTIProcess))
		return false;
	printf("\r\n=====Stopping TermService Service======");
	DoStopSvc("TermService");
	//Deleting the modified termsrv.dll
	printf("\r\n=========Deleting Termsrv.dll==========\r\n");
	DeleteFileW(wcTargetFilePath);
	//Moving the unmodified termsrv.dll.backup to termsrv.dll
	printf("\r\n\r\n==========Moving Termsrv.dll===========\r\n");
	printf("\r\nSrc Path: %ls", wcBackupFilePath);
	printf("\r\nDst Path: %ls", wcTargetFilePath);
	if (!BMoveTIFile(wcBackupFilePath, wcTargetFilePath))
		return false;
	//Revert registry
	//HKLM\Microsoft\Windows NT\CurrentVersion\TerminalServer\TSAppAllowList\fDisabledAllowList -> 0
	printf("\r\n\r\n=====Registry fDisabledAllowList=======");
	printf("\r\nReverting Terminal Server\\TSAppAllowList\\fDisabledAllowList to 0.");
	printf("\r\nThis will only work on x64. You lazy slob.");
	if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, TEXT("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Terminal Server\\TSAppAllowList"), 0, KEY_ALL_ACCESS | KEY_WOW64_64KEY, &key) != ERROR_SUCCESS)
	{
		printf("\r\nUnable to find TSAppAllowList");
		return false;
	}
	if (RegQueryValueEx(key, TEXT("fDisabledAllowList"), NULL, &dwType, (LPBYTE)&dwFDisabledAllowList, &dwSize) != ERROR_SUCCESS)
	{
		printf("\r\nUnable to find fDisabledAllowList");
		return false;
	}
	printf("\r\nfDisabledAllowList Value: %ld", dwFDisabledAllowList);
	if (dwFDisabledAllowList == 1)
	{
		if (RegSetValueEx(key, TEXT("fDisabledAllowList"), NULL, dwType, (LPBYTE)&dwFDisabledAllowListSet, dwSize) != ERROR_SUCCESS)
		{
			printf("\r\nUnable to set fDisabledAllowList to 0");
			return false;
		}
		if (RegQueryValueEx(key, TEXT("fDisabledAllowList"), NULL, &dwType, (LPBYTE)&dwFDisabledAllowList, &dwSize) != ERROR_SUCCESS)
		{
			printf("\r\nUnable to find fDisabledAllowList");
			return false;
		}
		printf("\r\nfDisabledAllowList Value: %ld", dwFDisabledAllowList);
	}
	printf("\r\n\r\n=====Starting TermService Service======");
	DoStartSvc("TermService");
	return true;
}