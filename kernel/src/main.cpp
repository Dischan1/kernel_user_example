#pragma comment(lib, "Ntoskrnl.lib")
#pragma comment(lib, "ntdll.lib")

#include <fltkernel.h>

#include "structs.h"
#include "common.h"
#include "utils.hpp"

#include "executable_import.hpp"
#include "executable_info.hpp"

#define log(format, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "process_name_spoofer!" __FUNCTION__ ": " format, __VA_ARGS__)

#define __auto_trace_log log("%i\n", __COUNTER__)
#define IndexOfNtQuerySystemInformation 54

EXTERN_C_START
DRIVER_DISPATCH		DriverDispath;
DRIVER_DISPATCH		DriverCreateClose;
DRIVER_DISPATCH		DriverRead;
DRIVER_DISPATCH		DriverWrite;
DRIVER_UNLOAD		DriverUnload;
DRIVER_INITIALIZE	DriverEntry;
EXTERN_C_END

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, DriverDispath)
#pragma alloc_text(PAGE, DriverCreateClose)
#pragma alloc_text(PAGE, DriverUnload)
#pragma alloc_text(INIT, DriverEntry)
#endif

UNICODE_STRING g_device_name   = RTL_CONSTANT_STRING(DRIVER_DEVICE_NAME);
UNICODE_STRING g_symbolic_link = RTL_CONSTANT_STRING(DRIVER_SYMBOLIC_LINK);

decltype(NtQuerySystemInformation)* NtQuerySystemInformation_original = nullptr;

executable_info::_info* executables;
FAST_MUTEX executables_mutex;

NTSTATUS NtQuerySystemInformation_detour(
	IN  SYSTEM_INFORMATION_CLASS SystemInformationClass,
	IN  PVOID                    SystemInformation,
	IN  ULONG                    SystemInformationLength,
	OUT PULONG                   ReturnLength)
{
	constexpr auto EQUAL = 0;

	static const UNICODE_STRING SPOOF_SOURCE = RTL_CONSTANT_STRING(SPOOF_PROCESS_NAME_SOURCE);
	static const UNICODE_STRING SPOOF_TARGET = RTL_CONSTANT_STRING(SPOOF_PROCESS_NAME_TARGET);

	if (SystemInformationClass != SystemProcessInformation)
		return NtQuerySystemInformation_original(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);

	if (!SystemInformation || !SystemInformationLength)
		return NtQuerySystemInformation_original(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);

	auto ntstatus = NtQuerySystemInformation_original(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
	if (!NT_SUCCESS(ntstatus) || !ReturnLength || !*ReturnLength) return ntstatus;

	auto spi = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(SystemInformation);
	auto end = reinterpret_cast<char*>(SystemInformation) + *ReturnLength;

	while (spi->NextEntryOffset && reinterpret_cast<char*>(spi) < end)
	{
		if (!spi->ImageName.Buffer)
		{
			reinterpret_cast<char*&>(spi) += spi->NextEntryOffset;
			continue;
		}

		if (RtlCompareUnicodeString(&spi->ImageName, &SPOOF_SOURCE, TRUE) == EQUAL)
		{
			auto length = static_cast<ULONGLONG>(SPOOF_TARGET.Length) + sizeof(SPOOF_TARGET.Buffer[0]);

			// !!! WARNING: disposed by executable exit only
			//
			void* address = allocate_user_memory<void*>(PsGetCurrentProcessId(), length);

			if (address)
			{
				memset(address, 0, length);
				memcpy(address, SPOOF_TARGET.Buffer, SPOOF_TARGET.Length);

				spi->ImageName.Buffer = reinterpret_cast<PWCH>(address);
			}
		}

		reinterpret_cast<char*&>(spi) += spi->NextEntryOffset;
	}

	return ntstatus;
}

VOID
register_executable(
	IN PUNICODE_STRING FullImageName, 
	IN PVOID module_base)
{
	auto base	= reinterpret_cast<char*>(module_base);
	auto dos	= reinterpret_cast<PIMAGE_DOS_HEADER>(base);
	auto nt		= reinterpret_cast<PIMAGE_NT_HEADERS>(base + dos->e_lfanew);
	auto opt	= reinterpret_cast<PIMAGE_OPTIONAL_HEADER>(&nt->OptionalHeader);
	auto desc	= reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(base + opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	ExAcquireFastMutex(&executables_mutex);

	for (; desc->Name; ++desc)
	{
		auto dll_name = reinterpret_cast<char*>(base + desc->Name);

		auto is_ssleay = strstr(dll_name, "libssl") != nullptr;
		auto is_dll    = strstr(dll_name, ".dll")   != nullptr;

		if (!dll_name || !is_ssleay || !is_dll) continue;

		auto thunk = reinterpret_cast<ULONG_PTR*>(base + desc->OriginalFirstThunk);
		auto func  = reinterpret_cast<ULONG_PTR*>(base + desc->FirstThunk);

		if (!thunk) thunk = func;

		auto exec_info = executable_info::allocate(FullImageName->Buffer);

		for (; *thunk; ++thunk, ++func)
		{
			if (IMAGE_SNAP_BY_ORDINAL(*thunk)) continue;

			auto import_by_name = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(base + (*thunk));

			auto exec_import = executable_import::allocate(func, import_by_name->Name);
			executable_info::insert_import(exec_info, exec_import);
		}

		executable_info::insert(executables, exec_info);
		
		break;
	}

	ExReleaseFastMutex(&executables_mutex);
}

VOID 
load_image_notify_routine(
	IN PUNICODE_STRING full_image_name, 
	IN HANDLE process_id, 
	IN PIMAGE_INFO image_info)
{
	if (!stristr(full_image_name->Buffer, L".exe"))
		return;

	PEPROCESS peprocess;
	PsLookupProcessByProcessId(process_id, &peprocess);
	{
		register_executable(full_image_name, image_info->ImageBase);
	}
	ObReferenceObject(peprocess);
}

NTSTATUS
DriverCreateClose(
	IN PDEVICE_OBJECT device_object, 
	IN PIRP irp)
{
	log("enter\n");
	UNREFERENCED_PARAMETER(device_object);

	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;

	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS
dispatch_read_imports(
	IN PDEVICE_OBJECT device_object, 
	IN IRP_INFO* irp)
{
	if (!irp->input.buff || !irp->output.buff)
		return STATUS_INVALID_PARAMETER;

	auto in_buff  = reinterpret_cast<char*>(irp->input.buff);
	auto out_buff = reinterpret_cast<char*>(irp->output.buff);

	auto in_size  = irp->input.size;
	auto out_size = irp->output.size;

	auto irp_data = reinterpret_cast<IRP_DATA_READ_IMPORTS*>(in_buff);

	if (!out_size || in_size != sizeof(IRP_DATA_READ_IMPORTS))
		return STATUS_INVALID_PARAMETER;

	if (!out_size)
		return STATUS_INVALID_PARAMETER;

	ExAcquireFastMutex(&executables_mutex);

	if (IsListEmpty(executables))
	{
		ExReleaseFastMutex(&executables_mutex);
		memset(out_buff, 0, out_size);
		return STATUS_SUCCESS;
	}

	auto e = reinterpret_cast<decltype(executables)>(executables->Flink);
	auto length = FIELD_OFFSET(_executable_data, name) + e->name.length;

	for (auto curr = e->imports->Flink; curr != e->imports; curr = curr->Flink)
	{
		auto import = reinterpret_cast<executable_import::_info*>(curr);
		length += FIELD_OFFSET(_import_data, name) + import->name.length;
	}

	if (!irp_data->size)
	{
		ExReleaseFastMutex(&executables_mutex);

		if (out_size != sizeof(IRP_DATA_READ_IMPORTS))
			return STATUS_INVALID_PARAMETER;

		memset(out_buff, 0, out_size);

		irp_data->size = length;
		irp->info_size = sizeof(IRP_DATA_READ_IMPORTS);

		return STATUS_SUCCESS;
	}

	if (out_size != length)
	{
		ExReleaseFastMutex(&executables_mutex);
		return STATUS_INVALID_PARAMETER;
	}

	length = 0u;

	auto exec_data = reinterpret_cast<_executable_data*>(reinterpret_cast<char*>(out_buff) + length);
	length = FIELD_OFFSET(_executable_data, name) + e->name.length;

	memcpy(exec_data->name, e->name.buffer, e->name.length);

	exec_data->offset.imports = length;

	auto imports = reinterpret_cast<_import_data*>(reinterpret_cast<char*>(exec_data) + exec_data->offset.imports);

	for (auto curr = e->imports->Flink; curr != e->imports; curr = curr->Flink)
	{
		auto import = reinterpret_cast<executable_import::_info*>(curr);
		auto offset = FIELD_OFFSET(_import_data, name) + import->name.length;

		imports->address = import->address;
		memcpy(imports->name, import->name.buffer, import->name.length);

		length += offset;

		if (curr->Flink != e->imports)
			imports->offset.next = offset;

		reinterpret_cast<char*&>(imports) += offset;
	}

	irp->info_size = length;

	executable_info::remove(e);
	executable_info::dispose(e);

	ExReleaseFastMutex(&executables_mutex);
	return STATUS_SUCCESS;
}

NTSTATUS
DriverDispatch(
	IN PDEVICE_OBJECT device_object, 
	IN PIRP irp)
{
	UNREFERENCED_PARAMETER(device_object);

	auto ntstatus = STATUS_SUCCESS;
	auto stack = IoGetCurrentIrpStackLocation(irp);

	__try
	{
		auto irp_ = IRP_INFO();
		irp_.ioctl_code = stack->Parameters.DeviceIoControl.IoControlCode;

		irp_.input.buff = irp->AssociatedIrp.SystemBuffer;
		irp_.input.size = stack->Parameters.DeviceIoControl.InputBufferLength;

		irp_.output.buff = irp->AssociatedIrp.SystemBuffer;
		irp_.output.size = stack->Parameters.DeviceIoControl.OutputBufferLength;

		irp_.info_size = 0;

		{
			switch (irp_.ioctl_code)
			{
				case IOCTL_READ_IMPORTS:
				{
					if (irp_.input.size != sizeof(IRP_DATA_READ_IMPORTS))
					{
						ntstatus = STATUS_INVALID_PARAMETER;
						break;
					}

					ntstatus = dispatch_read_imports(device_object, &irp_);
				}
				break;
			}
		}

		irp->IoStatus.Information = irp_.info_size;
		irp->IoStatus.Status = ntstatus;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		irp->IoStatus.Information = 0;
		irp->IoStatus.Status = STATUS_ACCESS_VIOLATION;
	}

	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

VOID
DriverUnload(
	IN PDRIVER_OBJECT driver_object)
{
	log("enter\n");
	UNREFERENCED_PARAMETER(driver_object);

	PsRemoveLoadImageNotifyRoutine(&load_image_notify_routine);

	executable_info::dispose(executables);

	if (NtQuerySystemInformation_original)
	{
		utils::page_protect_off();

		utils::ssdt()->ServiceTableBase[IndexOfNtQuerySystemInformation] = 
			utils::get_offset_address(reinterpret_cast<ULONGLONG>(NtQuerySystemInformation_original));

		utils::page_protect_on();
	}

	IoDeleteSymbolicLink(&g_symbolic_link);
	IoDeleteDevice(driver_object->DeviceObject);
}

NTSTATUS
DriverEntry(
	IN PDRIVER_OBJECT driver_object, 
	IN PUNICODE_STRING registry_path)
{
	log("enter\n");
	UNREFERENCED_PARAMETER(registry_path);

	NTSTATUS ntstatus = STATUS_SUCCESS;
	PDEVICE_OBJECT device_object = NULL;

	ntstatus = IoCreateDevice(driver_object, 0, &g_device_name, FILE_DEVICE_UNKNOWN, 0, FALSE, &device_object);
	if (!NT_SUCCESS(ntstatus)) return ntstatus;

	ntstatus = IoCreateSymbolicLink(&g_symbolic_link, &g_device_name);

	if (!NT_SUCCESS(ntstatus))
	{
		IoDeleteDevice(device_object);
		return ntstatus;
	}

	driver_object->Flags |= DO_BUFFERED_IO;

	driver_object->MajorFunction[IRP_MJ_CREATE] = DriverCreateClose;
	driver_object->MajorFunction[IRP_MJ_CLOSE]  = DriverCreateClose;
	driver_object->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverDispatch;
	driver_object->DriverUnload = DriverUnload;

	NtQuerySystemInformation_original = reinterpret_cast<decltype(NtQuerySystemInformation_original)>(
		(utils::ssdt()->ServiceTableBase[IndexOfNtQuerySystemInformation] >> 4) + (ULONG_PTR)utils::ssdt()->ServiceTableBase);

	if (NtQuerySystemInformation_original != reinterpret_cast<void*>(utils::get_func_address(L"NtQuerySystemInformation")))
	{
		NtQuerySystemInformation_original = nullptr;
		log("wrong NtQuerySystemInformation index\n");
		return ntstatus;
	}

	utils::page_protect_off();

	utils::ssdt()->ServiceTableBase[IndexOfNtQuerySystemInformation] = 
		utils::get_offset_address(reinterpret_cast<ULONGLONG>(&NtQuerySystemInformation_detour));

	utils::page_protect_on();

	executables = executable_info::allocate(L"");

	ExInitializeFastMutex(&executables_mutex);
	PsSetLoadImageNotifyRoutine(&load_image_notify_routine);

	return ntstatus;
}