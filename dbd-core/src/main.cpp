#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>

static DWORD get_process_id(const wchar_t* process_name) {
	DWORD process_id = 0;
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (snapshot == INVALID_HANDLE_VALUE) {
		return process_id;
	}


	PROCESSENTRY32W process_entry = {};
	process_entry.dwSize = sizeof(decltype(process_entry));
	if (Process32FirstW(snapshot, &process_entry) == TRUE) {
		do {
			if (_wcsicmp(process_name, process_entry.szExeFile) == 0) {
				process_id = process_entry.th32ProcessID;
				break;
			}
		} while (Process32NextW(snapshot, &process_entry));
	}
	CloseHandle(snapshot);
	return process_id;
}

static std::uintptr_t get_module_base(DWORD process_id, const wchar_t* module_name) {
	std::uintptr_t base_address = 0;
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, process_id);
	if (snapshot == INVALID_HANDLE_VALUE) {
		return base_address;
	}

	MODULEENTRY32W module_entry = {};
	module_entry.dwSize = sizeof(decltype(module_entry));
	if (Module32FirstW(snapshot, &module_entry) == TRUE) {
		do {
			if (wcsstr(module_name, module_entry.szModule) != nullptr) {
				base_address = reinterpret_cast<std::uintptr_t>(module_entry.modBaseAddr);
				break;
			}
		} while (Module32NextW(snapshot, &module_entry));
	}
	CloseHandle(snapshot);
	return base_address;
}

namespace driver {
	namespace codes {
		// Used to attach to a process
		constexpr ULONG attach =
			CTL_CODE(FILE_DEVICE_UNKNOWN, 0x696, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);

		// Used to read and write memory
		constexpr ULONG read =
			CTL_CODE(FILE_DEVICE_UNKNOWN, 0x697, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);

		constexpr ULONG write =
			CTL_CODE(FILE_DEVICE_UNKNOWN, 0x698, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
	} // namespace codes

	struct Request {
		HANDLE process_id;

		PVOID target;
		PVOID buffer;

		SIZE_T size;
		SIZE_T return_size;
	};

	bool attach_to_process(HANDLE driver_handle, const DWORD pid) {
		Request request;

		request.process_id = reinterpret_cast<HANDLE>(pid);

		return DeviceIoControl(driver_handle, codes::attach, &request, sizeof(request), &request, sizeof(request), nullptr, nullptr);
	}

	template <class T>
	T read_memory(HANDLE driver_handle, const std::uintptr_t address) {
		T temp = {};

		Request request;
		request.target = reinterpret_cast<PVOID>(address);
		request.buffer = &temp;
		request.size = sizeof(T);

		DeviceIoControl(driver_handle, codes::read, &request, sizeof(request), &request, sizeof(request), nullptr, nullptr);

		return temp;
	}

	template <class T>
	void write_memory(HANDLE driver_handle, const std::uintptr_t address, const T& buffer) {
		Request request;
		request.target = reinterpret_cast<PVOID>(address);
		request.buffer = (PVOID)&buffer;
		request.size = sizeof(T);

		DeviceIoControl(driver_handle, codes::write, &request, sizeof(request), &request, sizeof(request), nullptr, nullptr);
	}
};

int main() {
	
	CONST DWORD pid = get_process_id(L"notepad.exe");

	if (pid == 0) {
		std::wcout << L"[-] Failed to get process id" << std::endl;
		std::cin.get();
		return 1;
	}

	std::wcout << L"[+] Found process id: " << pid << std::endl;

	const HANDLE driver_handle = CreateFile(L"\\\\.\\kmDriver", GENERIC_READ, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

	if (driver_handle == INVALID_HANDLE_VALUE) {
		std::wcout << L"[-] Failed to get driver handle" << std::endl;
		std::cin.get();
		return 1;
	}

	std::wcout << L"[+] Got driver handle" << std::endl;

	if (!driver::attach_to_process(driver_handle, pid)) {
		std::wcout << L"[-] Failed to attach to process" << std::endl;
		std::cin.get();
		return 1;
	}

	std::wcout << L"[+] Attached to process" << std::endl;

	CloseHandle(driver_handle);

	std::cin.get();

	return 0;
}