#pragma once

EXTERN_C_START
void __writecr0(unsigned __int64 Data);
unsigned __int64 __readcr0(void);
unsigned __int64 __readmsr(int);
void __writemsr(int, __int64);

void __debugbreak();
void _disable(void);
void _enable(void);
EXTERN_C_END

template<typename T>
auto allocate_kernel_memory(size_t size) -> T
{
	auto buffer = ExAllocatePoolWithTag(PagedPool, size, 'csiD');
	while (!buffer) buffer = ExAllocatePoolWithTag(PagedPool, size, 'csiD');
	return reinterpret_cast<T>(buffer);
}

template<typename T>
auto allocate_user_memory(HANDLE process_id, size_t size) -> T
{
	void* address = nullptr;
	auto peprocess = PEPROCESS();
	auto hprocess = HANDLE();

	auto ntstatus = PsLookupProcessByProcessId(process_id, &peprocess);
	if (!NT_SUCCESS(ntstatus)) goto lexitempty;

	ntstatus = ObOpenObjectByPointer(peprocess, OBJ_KERNEL_HANDLE, NULL, 0, NULL, KernelMode, &hprocess);
	if (!NT_SUCCESS(ntstatus)) goto lexitdereference;

	ntstatus = ZwAllocateVirtualMemory(hprocess, &address, NULL, &size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!NT_SUCCESS(ntstatus)) goto lexitclose;

lexitclose:
	ZwClose(hprocess);
lexitdereference:
	ObDereferenceObject(peprocess);
lexitempty:
	return reinterpret_cast<T>(address);
}

namespace utils
{
	auto stristr(const wchar_t* String, const wchar_t* Pattern) -> wchar_t*;
	auto ssdt() -> PSYSTEM_SERVICE_TABLE;
	auto get_func_address(PWSTR FuncName) -> ULONG_PTR;
	auto get_offset_address(ULONGLONG _FuncAddr) -> ULONG;
	auto page_protect_off() -> VOID;
	auto page_protect_on() -> VOID;
}

auto stristr(const wchar_t* String, const wchar_t* Pattern) -> wchar_t*
{
	wchar_t* pptr, * sptr, * start;

	for (start = (wchar_t*)String; *start != NULL; ++start)
	{
		while (((*start != NULL) && (RtlUpcaseUnicodeChar(*start)
			!= RtlUpcaseUnicodeChar(*Pattern))))
		{
			++start;
		}

		if (NULL == *start)
			return NULL;

		pptr = (wchar_t*)Pattern;
		sptr = (wchar_t*)start;

		while (RtlUpcaseUnicodeChar(*sptr) == RtlUpcaseUnicodeChar(*pptr))
		{
			sptr++;
			pptr++;

			if (NULL == *pptr)
				return (wchar_t*)start;
		}
	}

	return NULL;
}

auto utils::ssdt() -> PSYSTEM_SERVICE_TABLE
{
	static ULONG_PTR pSSDT = NULL;
	if (pSSDT) return reinterpret_cast<PSYSTEM_SERVICE_TABLE>(pSSDT);

	ULONG_PTR SystemCall64 = __readmsr(0xC0000082);
	ULONG_PTR StartAddress = SystemCall64;
	ULONG_PTR EndAddress = StartAddress + 0x500;

	while (StartAddress < EndAddress)
	{
		UCHAR* p = (UCHAR*)StartAddress;
		if (MmIsAddressValid(p) && MmIsAddressValid(p + 1) && MmIsAddressValid(p + 2))
		{
			if (*p == 0x4c && *(p + 1) == 0x8d && *(p + 2) == 0x15)
			{
				pSSDT = (ULONG_PTR)(*(ULONG*)(p + 3)) + (ULONG_PTR)(p + 7);
				break;
			}
		}
		++StartAddress;
	}

	return reinterpret_cast<PSYSTEM_SERVICE_TABLE>(pSSDT);
}

auto utils::get_func_address(PWSTR FuncName) -> ULONG_PTR
{
	UNICODE_STRING uFunctionName;
	RtlInitUnicodeString(&uFunctionName, FuncName);
	return (ULONG_PTR)MmGetSystemRoutineAddress(&uFunctionName);
}

auto utils::get_offset_address(ULONGLONG _FuncAddr) -> ULONG
{ // https://github.com/PowerfulGun/HookorUnhookSSDT/blob/master/HookSSDT/HookSSDT.c#L263
	ULONG	dwOffset = 0;
	PULONG	ServiceTableBase = NULL;

	auto pssdt = reinterpret_cast<PSYSTEM_SERVICE_TABLE>(ssdt());
	ServiceTableBase = (PULONG)pssdt->ServiceTableBase;
	dwOffset = (ULONG)(_FuncAddr - (ULONGLONG)ServiceTableBase);

	return dwOffset << 4;
}

auto utils::page_protect_off() -> VOID
{
	ULONG_PTR cr0;
	_disable();
	cr0 = __readcr0();
	cr0 &= 0xfffffffffffeffff;
	__writecr0(cr0);
}

auto utils::page_protect_on() -> VOID
{
	ULONG_PTR cr0;
	cr0 = __readcr0();
	cr0 |= 0x10000;
	__writecr0(cr0);
	_enable();
}