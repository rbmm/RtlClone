#include "stdafx.h"
#include "resource.h"

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

int ShowErrorBox(HWND hwnd, NTSTATUS status, PCWSTR lpCaption, UINT uType)
{
	int r = 0;

	PWSTR lpText;
	if (FormatMessageW(FORMAT_MESSAGE_FROM_HMODULE | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS, 
		GetModuleHandle(L"ntdll"), status, 0, (PWSTR)&lpText, 0, 0))
	{
		r = MessageBoxW(hwnd, lpText, lpCaption, uType);
		LocalFree(lpText);
	}

	return r;
}

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

NTSTATUS OpenSection(_Out_ PHANDLE SectionHandle, _In_ PCWSTR lpLibFileName)
{
	int len = 0;
	PWSTR buf = 0;

	while (0 < (len = _snwprintf(buf, len, L"\\KnownDlls\\%s", lpLibFileName)))
	{
		if (buf)
		{
			UNICODE_STRING ObjectName;
			OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, &ObjectName, OBJ_CASE_INSENSITIVE };
			RtlInitUnicodeString(&ObjectName, buf);

			return NtOpenSection(SectionHandle, SECTION_MAP_EXECUTE, &oa);
		}

		buf = (PWSTR)alloca(++len * sizeof(WCHAR));
	}

	return STATUS_INTERNAL_ERROR;
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

NTSTATUS CreateOrOpenSection(_Out_ PHANDLE SectionHandle, _In_ PCWSTR lpLibFileName)
{
	NTSTATUS status = OpenSection(SectionHandle, lpLibFileName);
	return 0 > status ? CreateSection(SectionHandle, lpLibFileName) : STATUS_SUCCESS;
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
		if (0 <= (status = CreateOrOpenSection(&hSection, lpLibFileName)))
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

		if (0 <= (status = NtOpenThread(&hThread, DesiredAccess|THREAD_QUERY_LIMITED_INFORMATION, &oa, ClientId)))
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

NTSTATUS fork(_In_ HWND hwnd, _In_ PCWSTR lpLibFileName = 0, _In_ PVOID BaseAddress = 0, _In_ int index = -1)
{
	HANDLE hProcess, hThread;

	BAS ba { 0, STATUS_UNSUCCESSFUL };

	CLIENT_ID cid = { (HANDLE)(ULONG_PTR)GetCurrentProcessId(), (HANDLE)(ULONG_PTR)GetCurrentThreadId() };

	NTSTATUS status = CloneUserProcess(&hProcess, &hThread, TRUE, 0, 0);

	if (STATUS_PROCESS_CLONED == status)
	{
		// ++ cloned process

		if (0 <= (status = OpenParentThread(&hThread, THREAD_ALERT|THREAD_SET_CONTEXT, &cid)))
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
			if (0 > ba.status)
			{
				ShowErrorBox(hwnd, ba.status, lpLibFileName, MB_ICONHAND);
			}
			else
			{
				WCHAR msg[0x40];
				HWND hwndCB = GetDlgItem(hwnd, IDC_COMBO1);

				if (BaseAddress)
				{
					if (0 <= (index = ComboBox_DeleteString(hwndCB, index)))
					{
						ComboBox_SetCurSel(hwndCB, index - 1);

						if (!index)
						{
							EnableWindow(GetDlgItem(hwnd, IDC_BUTTON4), FALSE);
						}
					}
					swprintf_s(msg, _countof(msg), L"unload at %p", BaseAddress);
				}
				else if (lpLibFileName)
				{
					swprintf_s(msg, _countof(msg), L"mapped at %p", ba.BaseAddress);

					if (0 <= (index = ComboBox_AddString(hwndCB, msg + _countof("mapped at"))))
					{
						ComboBox_SetItemData(hwndCB, index, ba.BaseAddress);
						ComboBox_SetCurSel(hwndCB, index);

						if (!index) EnableWindow(GetDlgItem(hwnd, IDC_BUTTON4), TRUE);
					}
				}
				MessageBoxW(hwnd, msg, lpLibFileName, MB_ICONINFORMATION);
			}
		}
	}

	return status;
}

NTSTATUS fork()
{
	HANDLE hProcess, hThread, hEvent;

	OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, 0, OBJ_INHERIT };

	NTSTATUS status = NtCreateEvent(&hEvent, EVENT_ALL_ACCESS, &oa, NotificationEvent, FALSE);

	if (0 <= status)
	{
		status = CloneUserProcess(&hProcess, &hThread, TRUE, PROCESS_CREATE_FLAGS_INHERIT_HANDLES, 0);

		if (STATUS_PROCESS_CLONED == status)
		{
			// ++ cloned process
			status = NtSetEvent(hEvent, 0);
			NtClose(hEvent);
			NtTerminateProcess(NtCurrentProcess(), status);
			// -- cloned process
		}

		if (0 <= status)
		{
			NtClose(hThread);

			HANDLE Handles[2] = { hProcess, hEvent };
			// really possible raise, if NtTerminateProcess will be called before NtWaitForMultipleObjects
			// will be STATUS_WAIT_0 instead STATUS_WAIT_1 (both hEvent and hProcess is signaled)
			status = NtWaitForMultipleObjects(_countof(Handles), Handles, WaitAny, TRUE, 0);

			NtClose(hProcess);
		}

		NtClose(hEvent);
	}

	return status;
}

NTSTATUS OnCmd(HWND hwnd, WPARAM wParam, LPARAM lParam)
{
	switch (wParam)
	{
	case MAKEWPARAM(IDC_BUTTON1, BN_CLICKED):
		return fork();

	case MAKEWPARAM(IDC_BUTTON2, BN_CLICKED):
		return fork(0);

	case MAKEWPARAM(IDC_BUTTON3, BN_CLICKED):
		lParam = (LPARAM)alloca(0x100*sizeof(WCHAR));
		if (GetDlgItemTextW(hwnd, IDC_EDIT1, (PWSTR)lParam, 0x100))
		{
			return fork(hwnd, (PWSTR)lParam);
		}
		break;

	case MAKEWPARAM(IDC_BUTTON4, BN_CLICKED):
		if (0 <= (lParam = ComboBox_GetCurSel(GetDlgItem(hwnd, IDC_COMBO1))))
		{
			fork(hwnd, 0, (PVOID)ComboBox_GetItemData(GetDlgItem(hwnd, IDC_COMBO1), lParam), (int)lParam);
		}
		break;

	case IDCANCEL:
		EndDialog(hwnd, 0);
		break;

	case MAKEWPARAM(IDC_EDIT1, EN_CHANGE):
		EnableWindow(GetDlgItem(hwnd, IDC_BUTTON3), GetWindowTextLengthW((HWND)lParam));
		break;

	case MAKEWPARAM(IDC_COMBO1, CBN_SELCHANGE):
		EnableWindow(GetDlgItem(hwnd, IDC_BUTTON4), 0 <= ComboBox_GetCurSel((HWND)lParam));
		break;
	}

	return STATUS_MORE_PROCESSING_REQUIRED;
}

INT_PTR CALLBACK DlgProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch (uMsg)
	{
	case WM_COMMAND:
		switch (NTSTATUS status = OnCmd(hwnd, wParam, lParam))
		{
		case STATUS_MORE_PROCESSING_REQUIRED:
			break;
		default:
			ShowErrorBox(hwnd, status, L"Result:", MB_ICONINFORMATION);
		}
		break;

	case WM_INITDIALOG:
		SendDlgItemMessageW(hwnd, IDC_EDIT1, EM_SETCUEBANNER, TRUE, (LPARAM)L"enter <name.dll> from %windir%\\system32");
		break;
	}

	return 0;
}

void WINAPI ep(void* )
{
	ExitProcess((UINT)DialogBoxParamW((HINSTANCE)&__ImageBase, MAKEINTRESOURCE(IDD_DIALOG1), 0, DlgProc, 0));
}