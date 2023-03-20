#pragma once

#define DRIVER_DEVICE_NAME		L"\\Device\\process_name_spoofer"
#define DRIVER_SYMBOLIC_LINK	L"\\??\\process_name_spoofer"

#define SPOOF_PROCESS_NAME_SOURCE L"user.exe"
#define SPOOF_PROCESS_NAME_TARGET L"userxxx.exe"

#define IOCTL_READ_IMPORTS		CTL_CODE(0x8000, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

struct IRP_INFO
{
	struct
	{
		ULONG size;
		void* buff;
	} input;
	
	struct
	{
		ULONG size;
		void* buff;
	} output;

	ULONG info_size;
	ULONG ioctl_code;
};

struct _import_data
{
	struct
	{
		ULONG next;
	} offset;

	void* address;
	char name[1];
};

struct _executable_data
{
	struct
	{
		ULONG next;
		ULONG imports;
	} offset;

	wchar_t name[1];
	_import_data imports[1];
};

struct IRP_DATA_READ_IMPORTS
{
	ULONG size;
};

typedef struct _SYSTEM_PROCESS_INFORMATION {
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	UCHAR Reserved1[48];
	UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId;
	PVOID Reserved2;
	ULONG HandleCount;
	ULONG SessionId;
	PVOID Reserved3;
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG Reserved4;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	PVOID Reserved5;
	SIZE_T QuotaPagedPoolUsage;
	PVOID Reserved6;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER Reserved7[6];
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

extern "C" NTSTATUS NtQuerySystemInformation(
	IN  SYSTEM_INFORMATION_CLASS SystemInformationClass,
	IN  PVOID                    SystemInformation,
	IN  ULONG                    SystemInformationLength,
	OUT PULONG                   ReturnLength
);