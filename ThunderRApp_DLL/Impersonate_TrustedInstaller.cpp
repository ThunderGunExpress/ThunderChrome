//Run Programs as Trusted Installer
//https://github.com/lilkui/runasti

#include "Header.h"

void enable_privilege(string privilege_name)
{
	HANDLE token_handle;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &token_handle))
		throw runtime_error("OpenProcessToken failed: " + to_string(GetLastError()));

	LUID luid;
	if (!LookupPrivilegeValueA(nullptr, privilege_name.c_str(), &luid))
	{
		CloseHandle(token_handle);
		throw runtime_error("LookupPrivilegeValue failed: " + to_string(GetLastError()));
	}

	TOKEN_PRIVILEGES tp;
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	if (!AdjustTokenPrivileges(token_handle, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr))
	{
		CloseHandle(token_handle);
		throw runtime_error("AdjustTokenPrivilege failed: " + to_string(GetLastError()));
	}

	CloseHandle(token_handle);
}

DWORD get_process_id_by_name(const string process_name)
{
	HANDLE snapshot_handle;
	if ((snapshot_handle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)) == INVALID_HANDLE_VALUE)
	{
		throw runtime_error("CreateToolhelp32Snapshot failed: " + to_string(GetLastError()));
	}

	DWORD pid = -1;
	PROCESSENTRY32 pe;
	//ZeroMemory(&pe, sizeof(PROCESSENTRY32W));
	ZeroMemory(&pe, sizeof(PROCESSENTRY32));
	pe.dwSize = sizeof(PROCESSENTRY32W);
	if (Process32First(snapshot_handle, &pe))
	{
		while (Process32Next(snapshot_handle, &pe))
		{
			if (pe.szExeFile == process_name)
			{
				pid = pe.th32ProcessID;
				break;
			}
		}
	}
	else
	{
		CloseHandle(snapshot_handle);
		throw runtime_error("Process32First failed: " + to_string(GetLastError()));
	}

	if (pid == -1)
	{
		CloseHandle(snapshot_handle);
		throw runtime_error("process not found: " + process_name);
	}

	CloseHandle(snapshot_handle);
	return pid;
}

void impersonate_system()
{
	const auto system_pid = get_process_id_by_name("winlogon.exe");
	HANDLE process_handle;
	if ((process_handle = OpenProcess(
		PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION,
		FALSE,
		system_pid)) == nullptr)
	{
		throw runtime_error("OpenProcess failed (winlogon.exe): " + to_string(GetLastError()));
	}

	HANDLE token_handle;
	if (!OpenProcessToken(
		process_handle,
		MAXIMUM_ALLOWED,
		&token_handle))
	{
		CloseHandle(process_handle);
		throw runtime_error("OpenProcessToken failed (winlogon.exe): " + to_string(GetLastError()));
	}

	HANDLE dup_token_handle;
	SECURITY_ATTRIBUTES token_attributes;
	token_attributes.nLength = sizeof(SECURITY_ATTRIBUTES);
	token_attributes.lpSecurityDescriptor = nullptr;
	token_attributes.bInheritHandle = FALSE;
	if (!DuplicateTokenEx(
		token_handle,
		MAXIMUM_ALLOWED,
		&token_attributes,
		SecurityImpersonation,
		TokenImpersonation,
		&dup_token_handle))
	{
		CloseHandle(token_handle);
		throw runtime_error("DuplicateTokenEx failed (winlogon.exe): " + to_string(GetLastError()));
	}

	if (!ImpersonateLoggedOnUser(dup_token_handle))
	{
		CloseHandle(dup_token_handle);
		CloseHandle(token_handle);
		throw runtime_error("ImpersonateLoggedOnUser failed: " + to_string(GetLastError()));
	}

	CloseHandle(dup_token_handle);
	CloseHandle(token_handle);
}

int start_trusted_installer_service()
{
	SC_HANDLE sc_manager_handle;
	if ((sc_manager_handle = OpenSCManager(
		nullptr,
		SERVICES_ACTIVE_DATABASE,
		GENERIC_EXECUTE)) == nullptr)
	{
		printf("\r\nOpenSCManager failed.");
		return false;
	}

	SC_HANDLE service_handle;
	if ((service_handle = OpenServiceW(
		sc_manager_handle,
		L"TrustedInstaller",
		GENERIC_READ | GENERIC_EXECUTE)) == nullptr)
	{
		CloseServiceHandle(sc_manager_handle);
		printf("\r\nOpenService failed.");
		return false;
	}

	SERVICE_STATUS_PROCESS status_buffer;
	DWORD bytes_needed;
	while (QueryServiceStatusEx(
		service_handle,
		SC_STATUS_PROCESS_INFO,
		reinterpret_cast<LPBYTE>(&status_buffer),
		sizeof(SERVICE_STATUS_PROCESS),
		&bytes_needed))
	{
		if (status_buffer.dwCurrentState == SERVICE_STOPPED)
		{
			if (!StartServiceW(service_handle, 0, nullptr))
			{
				CloseServiceHandle(service_handle);
				CloseServiceHandle(sc_manager_handle);
				printf("\r\nStartService failed.");
				return false;
			}
		}
		if (status_buffer.dwCurrentState == SERVICE_START_PENDING ||
			status_buffer.dwCurrentState == SERVICE_STOP_PENDING)
		{
			Sleep(status_buffer.dwWaitHint);
			continue;
		}
		if (status_buffer.dwCurrentState == SERVICE_RUNNING)
		{
			CloseServiceHandle(service_handle);
			CloseServiceHandle(sc_manager_handle);
			stTarget.dwTIProcess = status_buffer.dwProcessId;
			return true;
		}
	}
	CloseServiceHandle(service_handle);
	CloseServiceHandle(sc_manager_handle);
	printf("\r\nQueryServiceStatusEx failed.");
	return false;
}

bool impersonate_trusted_installer(const DWORD pid)
{
	//enable_privilege(SE_DEBUG_NAME);
	enable_privilege("SeDebugPrivilege");
	//enable_privilege(SE_IMPERSONATE_NAME);
	enable_privilege("SeImpersonatePrivilege");
	impersonate_system();

	HANDLE process_handle;
	if ((process_handle = OpenProcess(
		PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION,
		FALSE,
		pid)) == nullptr)
	{
		printf("\r\nOpenProcess failed - TrustedInstaller.exe");
		return false;
	}

	HANDLE token_handle;
	if (!OpenProcessToken(
		process_handle,
		MAXIMUM_ALLOWED,
		&token_handle))
	{
		CloseHandle(process_handle);
		printf("\r\nOpenProcessToken failed - TrustedInstaller.exe");
		return false;
	}

	HANDLE dup_token_handle;
	SECURITY_ATTRIBUTES token_attributes;
	token_attributes.nLength = sizeof(SECURITY_ATTRIBUTES);
	token_attributes.lpSecurityDescriptor = nullptr;
	token_attributes.bInheritHandle = FALSE;
	if (!DuplicateTokenEx(
		token_handle,
		MAXIMUM_ALLOWED,
		&token_attributes,
		SecurityImpersonation,
		TokenImpersonation,
		&dup_token_handle))
	{
		CloseHandle(token_handle);
		printf("\r\nDuplicateTokenEx failed - TrustedInstaller.exe");
		return false;
	}
	ImpersonateLoggedOnUser(dup_token_handle);
	return true;
}