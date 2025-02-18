#include "stdafx.h"

EXTERN_C_START

NTSYSAPI
NTSTATUS
NTAPI
RtlPrepareForProcessCloning();

NTSYSAPI
NTSTATUS
NTAPI
RtlCompleteProcessCloning(_In_ BOOL bCloned);

EXTERN_C_END

NTSTATUS CloneUserProcess(_Out_ PHANDLE ProcessHandle,
	_Out_ PHANDLE ThreadHandle,
	_In_ BOOL bSynchronize,
	_In_ ULONG ProcessFlags, // PROCESS_CREATE_FLAGS_*
	_In_ ULONG ThreadFlags // THREAD_CREATE_FLAGS_*
)
{
	NTSTATUS status = bSynchronize ? RtlPrepareForProcessCloning() : STATUS_SUCCESS;

	if (0 <= status)
	{
		PS_CREATE_INFO createInfo = { sizeof(createInfo) };

		status = NtCreateUserProcess(ProcessHandle,
			ThreadHandle, PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS, NULL, NULL,
			ProcessFlags, ThreadFlags, NULL, &createInfo, NULL);

		if (IsDebuggerPresent()) __debugbreak();

		if (bSynchronize) RtlCompleteProcessCloning(STATUS_PROCESS_CLONED == status);
	}

	return status;
}

NTSTATUS CreateSection(_Out_ PHANDLE SectionHandle, _In_ PCWSTR lpLibFileName)
{
	int len = 0;
	PWSTR buf = 0;

	while (0 < (len = _snwprintf(buf, len, L"\\systemroot\\system32\\%s", lpLibFileName)))
	{
		if (buf)
		{
			UNICODE_STRING ObjectName;
			OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, &ObjectName, OBJ_CASE_INSENSITIVE };
			RtlInitUnicodeString(&ObjectName, buf);

			HANDLE hFile;
			IO_STATUS_BLOCK iosb;
			NTSTATUS status = NtOpenFile(&hFile, FILE_EXECUTE | SYNCHRONIZE, &oa, &iosb, FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT);

			if (0 <= status)
			{
				status = NtCreateSection(SectionHandle, SECTION_MAP_EXECUTE, 0, 0, PAGE_EXECUTE, SEC_IMAGE, hFile);
				NtClose(hFile);
			}

			return status;
		}

		buf = (PWSTR)alloca(++len * sizeof(WCHAR));
	}

	return STATUS_INTERNAL_ERROR;
}

struct BAS {
	PVOID BaseAddress;
	NTSTATUS status;
};

void NTAPI OnApc(
	_In_opt_ PVOID ApcArgument1,
	_In_opt_ PVOID ApcArgument2,
	_In_opt_ PVOID ApcArgument3)
{
	reinterpret_cast<BAS*>(ApcArgument1)->BaseAddress = ApcArgument2;
	reinterpret_cast<BAS*>(ApcArgument1)->status = (NTSTATUS)(ULONG_PTR)ApcArgument3;
}

NTSTATUS NotifyParent(_In_ HANDLE hThread, _In_ PVOID BaseAddress, _In_ BAS* p, NTSTATUS status)
{
	return NtQueueApcThread(hThread, OnApc, p, BaseAddress, (PVOID)(ULONG_PTR)status);
}

NTSTATUS DoRemoteMap(
	_In_ PCWSTR lpLibFileName,
	_In_ PCLIENT_ID ClientId,
	_In_ HANDLE hThread,
	_In_ BAS* p)
{
	HANDLE hProcess, hSection;

	BOOL bPost = FALSE;

	NTSTATUS status;

	OBJECT_ATTRIBUTES oa = { sizeof(oa) };

	if (0 <= (status = NtOpenProcess(&hProcess, PROCESS_VM_OPERATION, &oa, ClientId)))
	{
		if (0 <= (status = CreateSection(&hSection, lpLibFileName)))
		{
			SIZE_T ViewSize = 0;
			PVOID BaseAddress = 0;

			//////////////////////////////////////////////////////////////////////////
			//
			// ERROR: Unable to find system process ****
			// ERROR: The process being debugged has either exited or cannot be accessed
			// ERROR: Many commands will not work properly
			// ERROR: Module load event for unknown process
			//
			//////////////////////////////////////////////////////////////////////////

			status = ZwMapViewOfSection(hSection, hProcess, &BaseAddress,
				0, 0, 0, &ViewSize, ViewShare, 0, PAGE_EXECUTE);

			NtClose(hSection);

			if (0 <= status)
			{
				bPost = TRUE;

				if (0 > (status = NotifyParent(hThread, BaseAddress, p, status)))
				{
					ZwUnmapViewOfSection(hProcess, BaseAddress);
				}
			}
		}

		NtClose(hProcess);
	}

	if (!bPost) NotifyParent(hThread, 0, p, status);

	return status;
}

NTSTATUS DoRemoteUnMap(
	_In_ PVOID BaseAddress,
	_In_ PCLIENT_ID ClientId,
	_In_ HANDLE hThread,
	_In_ BAS* p)
{
	HANDLE hProcess;

	NTSTATUS status;

	OBJECT_ATTRIBUTES oa = { sizeof(oa) };

	if (0 <= (status = NtOpenProcess(&hProcess, PROCESS_VM_OPERATION, &oa, ClientId)))
	{
		status = ZwUnmapViewOfSection(hProcess, BaseAddress);

		NtClose(hProcess);
	}

	NotifyParent(hThread, BaseAddress, p, status);

	return status;
}

NTSTATUS OpenParentThread(_Out_ PHANDLE ThreadHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ PCLIENT_ID ClientId)
	/*
		thread with ClientId must be created *before* current thread
	*/
{
	NTSTATUS status;
	KERNEL_USER_TIMES kut, my_kut;

	if (0 <= (status = NtQueryInformationThread(NtCurrentThread(), ThreadTimes, &my_kut, sizeof(my_kut), 0)))
	{
		HANDLE hThread;
		OBJECT_ATTRIBUTES oa = { sizeof(oa) };

		if (0 <= (status = NtOpenThread(&hThread, DesiredAccess | THREAD_QUERY_LIMITED_INFORMATION, &oa, ClientId)))
		{
			if (0 <= (status = NtQueryInformationThread(hThread, ThreadTimes, &kut, sizeof(kut), 0)))
			{
				if (kut.CreateTime.QuadPart <= my_kut.CreateTime.QuadPart)
				{
					*ThreadHandle = hThread;
					return STATUS_SUCCESS;
				}

				// original thread terminated and other thread reuse it id
				status = STATUS_INVALID_CID;
			}

			NtClose(hThread);
		}
	}

	return status;
}

NTSTATUS fork(_Out_ void** phmod, _In_ PCWSTR lpLibFileName = 0, _In_ PVOID BaseAddress = 0)
{
	HANDLE hProcess, hThread;

	BAS ba{ 0, STATUS_UNSUCCESSFUL };

	CLIENT_ID cid = { (HANDLE)(ULONG_PTR)GetCurrentProcessId(), (HANDLE)(ULONG_PTR)GetCurrentThreadId() };

	NTSTATUS status = CloneUserProcess(&hProcess, &hThread, TRUE, 0, 0);

	if (STATUS_PROCESS_CLONED == status)
	{
		// ++ cloned process

		if (0 <= (status = OpenParentThread(&hThread, THREAD_ALERT | THREAD_SET_CONTEXT, &cid)))
		{
			status = BaseAddress ? DoRemoteUnMap(BaseAddress, &cid, hThread, &ba) :
				lpLibFileName ? DoRemoteMap(lpLibFileName, &cid, hThread, &ba) : NtAlertThread(hThread);

			NtClose(hThread);
		}

		NtTerminateProcess(NtCurrentProcess(), status);

		// -- cloned process
	}

	if (0 <= status)
	{
		NtClose(hThread);

		status = NtWaitForSingleObject(hProcess, TRUE, 0);

		NtClose(hProcess);

		if (STATUS_USER_APC == status)
		{
			DbgPrint("addr = %p, s = %x\n", ba.BaseAddress, ba.status);

			if (0 <= (status = ba.status))
			{
				*phmod = ba.BaseAddress;
			}
		}
		else
		{
			status = STATUS_UNSUCCESSFUL;
		}
	}

	return status;
}

void WINAPI ep(void*)
{
	MessageBoxW(0, 0, L"POC", MB_ICONWARNING);
	void* hmod;
	NTSTATUS status = fork(&hmod, L"kerberos.dll");
	WCHAR sz[0x40];
	if (0 > status)
	{
		swprintf_s(sz, _countof(sz), L"error = %x", status);
	}
	else
	{ 
		swprintf_s(sz, _countof(sz), L"hmod = %p", hmod);
	}
	MessageBoxW(0, sz, L"load kerberos", MB_ICONINFORMATION);

	if (0 <= status)
	{
		status = fork(&hmod, 0, hmod);
		swprintf_s(sz, _countof(sz), L"error = %x", status);
		MessageBoxW(0, sz, L"unload", MB_ICONINFORMATION);
	}

	ExitProcess(0);
}
