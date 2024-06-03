# RtlClone

from [The Definitive Guide To Process Cloning on Windows](https://github.com/huntandhackett/process-cloning/tree/master?tab=readme-ov-file#the-definitive-guide-to-process-cloning-on-windows)
 
So, why is RtlCloneUserProcess useful when we already have the more flexible NtCreateUserProcess? The reason might be surprising: we cannot re-implement its functionality, at least not entirely and precisely.

this is not true. ntdll.dll (native, not wow) exported next 2 functions:

```
NTSYSAPI
NTSTATUS
NTAPI
RtlPrepareForProcessCloning();

NTSYSAPI
NTSTATUS
NTAPI
RtlCompleteProcessCloning(_In_ BOOL bCloned);
```

with it we easy can implement RtlCloneUserProcess with NtCreateUserProcess

``
	NTSTATUS status = ProcessFlags & RTL_CLONE_PROCESS_FLAGS_NO_SYNCHRONIZE ? STATUS_SUCCESS : RtlPrepareForProcessCloning();

	if (0 <= status)
	{
		PS_CREATE_INFO createInfo = { sizeof(createInfo) };

		status = NtCreateUserProcess(...);

		if (ProcessFlags & RTL_CLONE_PROCESS_FLAGS_NO_SYNCHRONIZE) RtlCompleteProcessCloning(STATUS_PROCESS_CLONED == status);
	}

	return status;
```

such implementation we can view in wow64.dll inside Wow64NtCreateUserProcess function

probably it doesn't matter more, but it seems these api ( RtlPrepareForProcessCloning / RtlCompleteProcessCloning ) almost unknown, despite exist from win 8.1 (or 8)

in src code several example of how cloned process can interact with parent - via inherited Event handle, thread Alert, Apc, etc
also i show here again how we can map/unmap executable image section from cloned process to parent process. this is very strong anti-debug technique, most debuggers freeze both processes here forever. some debuggers silently, windbg with next messages:
```
      // ERROR: Unable to find system process ****
      // ERROR: The process being debugged has either exited or cannot be accessed
      // ERROR: Many commands will not work properly
      // ERROR: Module load event for unknown process
```
also this is work in x64 processes. but in x86 not exist RtlPrepareForProcessCloning/RtlCompleteProcessCloning

in case we in wow64 (x86 process on x64 system) NtCreateUserProcess internal call Wow64NtCreateUserProcess function inside wow64.dll
and it already call RtlPrepareForProcessCloning();NtCreateUserProcess(...);RtlCompleteProcessCloning(STATUS_PROCESS_CLONED == status); ( if RTL_CLONE_PROCESS_FLAGS_NO_SYNCHRONIZE not set )
despite new cloned wow64 process created - it crashed just after enter to 32-bit mode. more exactly - after first access FS segment. in x86 windows FS segment must point to thread TEB, but by error in cloning code - FS point to 0 in cloned process
