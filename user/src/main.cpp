#pragma comment(lib, "ntdll.lib")

#include <iostream>
#include <Windows.h>
#include <filesystem>

#include "ntos.h"
#include "common.h"

auto run_spoof_test() -> int
{
	constexpr auto EQUAL = 0;

	auto return_length = 0ul;

	NtQuerySystemInformation(SystemProcessInformation, nullptr, 0, &return_length);
	if (!return_length) return GetLastError();

	auto buffer = new char[return_length];
	auto end = buffer + return_length;
	auto spi = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(buffer);

	NtQuerySystemInformation(SystemProcessInformation, spi, return_length, &return_length);

	while (spi->NextEntryOffset && reinterpret_cast<char*>(spi) < end)
	{
		if (!spi->ImageName.Buffer)
		{
			reinterpret_cast<char*&>(spi) += spi->NextEntryOffset;
			continue;
		}

		if (_wcsicmp(spi->ImageName.Buffer, SPOOF_PROCESS_NAME_TARGET) == EQUAL)
		{
			printf("%S -> %S\n", SPOOF_PROCESS_NAME_SOURCE, spi->ImageName.Buffer);
			return delete[] buffer, ERROR_SUCCESS;
		}

		reinterpret_cast<char*&>(spi) += spi->NextEntryOffset;
	}

	delete[] buffer;
	return ERROR_PATH_NOT_FOUND;
}

auto run_read_imports_test() -> int
{
	auto hdriver = CreateFileW(DRIVER_SYMBOLIC_LINK, GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, FILE_FLAG_NO_BUFFERING, nullptr);

	if (!hdriver || hdriver == INVALID_HANDLE_VALUE)
		return GetLastError();

	auto input = IRP_DATA_READ_IMPORTS();

	auto status = DeviceIoControl(hdriver, IOCTL_READ_IMPORTS, &input, sizeof(input), &input, sizeof(input), nullptr, nullptr);
	if (!status) return GetLastError();

	if (!input.size) return ERROR_SUCCESS;

	auto output = reinterpret_cast<_executable_data*>(malloc(input.size));
	memcpy(output, &input, sizeof(input));

	status = DeviceIoControl(hdriver, IOCTL_READ_IMPORTS, &input, sizeof(input), output, input.size, nullptr, nullptr);
	if (!status) return GetLastError();

	auto e = reinterpret_cast<_executable_data*>(output);
	auto i = reinterpret_cast<_import_data*>(reinterpret_cast<char*>(e) + e->offset.imports);

	printf("%S\n", e->name);

	do
	{
		printf("\t%p %s\n", i->address, i->name);
	}
	while (i->offset.next && (reinterpret_cast<char*&>(i) += i->offset.next));

	free(output);
	CloseHandle(hdriver);

	return ERROR_SUCCESS;
}

auto process_tests() -> void
{
	if (auto code = run_spoof_test())
		printf("[-] spoof test error: %x\n", code);
	else
		printf("[+] spoof test passed\n");

	if (auto code = run_read_imports_test())
		printf("[-] read imports error: %x\n", code);
	else
		printf("[+] read imports passed\n");
}

int wmain(int argc, wchar_t* argv[])
{
	auto filename = std::filesystem::path(argv[0]).filename();

	if (filename.wstring() != SPOOF_PROCESS_NAME_SOURCE)
	{
		printf("to run tests, you need to rename the executable "
			"\\%S\\ to \\%S\\\n", filename.wstring().c_str(), SPOOF_PROCESS_NAME_SOURCE);
		return 0;
	}

	process_tests();
	system("pause");

	return 0;
}