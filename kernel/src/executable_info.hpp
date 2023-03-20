#pragma once

namespace executable_info
{
	struct _info : LIST_ENTRY
	{
		executable_import::_info* imports;

		struct
		{
			size_t length;
			wchar_t buffer[1];
		} name;
	};

	auto allocate(const wchar_t* name) -> _info*
	{
		auto length = wcslen(name) * sizeof(name[0]) + sizeof(name[0]);
		auto buffer = allocate_kernel_memory<_info*>(sizeof(_info) + length);
		auto v = reinterpret_cast<_info*>(buffer);

		InitializeListHead(v);

		v->name.length = length;

		memset(v->name.buffer, 0, length);
		memcpy(v->name.buffer, name, length - 1);

		return v->imports = executable_import::allocate(0, ""), v;
	}

	auto remove(_info* v)					-> void { RemoveEntryList(v); }
	auto insert(_info* main, _info* entry)	-> void { InsertHeadList(main, entry); }

	auto dispose(_info* info) -> void
	{
		for (auto curr = info->imports->Flink; curr != info->imports; curr = curr->Flink)
		{
			auto v = reinterpret_cast<executable_import::_info*>(curr);
			executable_import::dispose(v);
		}

		executable_import::dispose(info->imports);
		ExFreePoolWithTag(info, 'csiD');
	}

	auto insert_import(_info* main, executable_import::_info* entry) -> void
	{
		executable_import::insert(main->imports, entry);
	}
}