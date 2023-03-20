#pragma once

namespace executable_import
{
	struct _info : LIST_ENTRY
	{
		void* address;

		struct
		{
			size_t length;
			char buffer[1];
		} name;
	};

	auto allocate(void* address, const char* name) -> _info*
	{
		auto length = strlen(name) * sizeof(name[0]) + sizeof(name[0]);
		auto buffer = allocate_kernel_memory<_info*>(sizeof(_info) + length);
		auto v = reinterpret_cast<_info*>(buffer);

		InitializeListHead(v);

		v->name.length = length;

		memset(v->name.buffer, 0, length);
		memcpy(v->name.buffer, name, length - 1);

		return v->address = address, v;
	}

	auto remove(_info* v)					-> void { RemoveEntryList(v); }
	auto insert(_info* main, _info* entry)	-> void { InsertHeadList(main, entry); }
	auto dispose(_info* info)				-> void { ExFreePoolWithTag(info, 'csiD'); }
}