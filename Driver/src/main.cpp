#include <ntifs.h>

extern "C" {
	NTKERNELAPI NTSTATUS IoCreateDriver(PUNICODE_STRING DriverName, PDRIVER_INITIALIZE InitializationFunction);

	NTKERNELAPI NTSTATUS MmCopyVirtualMemory(PEPROCESS SourceProcess, PVOID SourceAddress,
											 PEPROCESS TargetProcess, PVOID TargetAddress,
											 SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode,
											 PSIZE_T ReturnSize);
}

void debugPrint(PCSTR text) {
#ifndef NDEBUG
	UNREFERENCED_PARAMETER(text);
#endif
	KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, text));
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

	NTSTATUS create(PDEVICE_OBJECT device, PIRP irp) {
		UNREFERENCED_PARAMETER(device);

		IoCompleteRequest(irp, IO_NO_INCREMENT);

		return irp->IoStatus.Status;
	}

	NTSTATUS close(PDEVICE_OBJECT device, PIRP irp) {
		UNREFERENCED_PARAMETER(device);

		IoCompleteRequest(irp, IO_NO_INCREMENT);

		return irp->IoStatus.Status;
	}


	//TODO: Implement this function
	NTSTATUS device_control(PDEVICE_OBJECT device, PIRP irp) {
		UNREFERENCED_PARAMETER(device);
		
		debugPrint("[+] Received IRP_MJ_DEVICE_CONTROL\n");

		NTSTATUS status = STATUS_UNSUCCESSFUL;

		PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
		
		auto request = reinterpret_cast<Request*>(irp->AssociatedIrp.SystemBuffer);

		if (request == nullptr || stack == nullptr) {
			debugPrint("[-] Invalid request\n");
			IoCompleteRequest(irp, IO_NO_INCREMENT);
			return status;
		}

		static PEPROCESS process = nullptr;

		const ULONG control_code = stack->Parameters.DeviceIoControl.IoControlCode;

		switch (control_code) {
			case codes::attach:
				status = PsLookupProcessByProcessId(request->process_id, &process);
				if (status != STATUS_SUCCESS) {
					debugPrint("[-] Failed to attach to process\n");
					break;
				}

				debugPrint("[+] Attached to process\n");
				break;

			case codes::read:
				if (process == nullptr) {
					debugPrint("[-] No process attached\n");
					break;
				}

				status = MmCopyVirtualMemory(process, request->target, PsGetCurrentProcess(), request->buffer, request->size, KernelMode, &request->return_size);
				break;
			
			case codes::write:
				if (process == nullptr) {
					debugPrint("[-] No process attached\n");
					break;
				}

				status = MmCopyVirtualMemory(PsGetCurrentProcess(), request->buffer, process, request->target, request->size, KernelMode, &request->return_size);
				break;

			default:
				debugPrint("[-] Invalid control code\n");
				break;

		}

		irp->IoStatus.Status = status;
		irp->IoStatus.Information = sizeof(Request);
		IoCompleteRequest(irp, IO_NO_INCREMENT);

		return status;
	}

} // namespace driver

NTSTATUS driver_main(PDRIVER_OBJECT driver_object, PUNICODE_STRING registry_path) {
	UNREFERENCED_PARAMETER(registry_path);

	UNICODE_STRING name = {};
	RtlInitUnicodeString(&name, L"\\Device\\kmDriver");

	PDEVICE_OBJECT device = nullptr;
	NTSTATUS status = IoCreateDevice(driver_object, 0, &name, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &device);

	if (status != STATUS_SUCCESS) {
		debugPrint("[-] Failed to create device\n");
		return status;
	}

	debugPrint("[+] Created driver device\n");

	UNICODE_STRING symlink = {};
	RtlInitUnicodeString(&symlink, L"\\DosDevices\\kmDriver");

	status = IoCreateSymbolicLink(&symlink, &name);
	if (status != STATUS_SUCCESS) {
		debugPrint("[-] Failed to establish driver symbolic link\n");
		IoDeleteDevice(device);
		return status;
	}

	debugPrint("[+] Established driver symbolic link\n");

	SetFlag(device->Flags, DO_BUFFERED_IO);
	
	driver_object->MajorFunction[IRP_MJ_CREATE] = driver::create;
	driver_object->MajorFunction[IRP_MJ_CLOSE] = driver::close;
	driver_object->MajorFunction[IRP_MJ_DEVICE_CONTROL] = driver::device_control;

	ClearFlag(device->Flags, DO_DEVICE_INITIALIZING);

	debugPrint("[+] Driver successfully initialized.\n");

	return status;
}

// params are null because of kdmapper
NTSTATUS DriverEntry() {
	debugPrint("[+] Setting up driver..\n");

	UNICODE_STRING name = {};
	RtlInitUnicodeString(&name, L"\\Driver\\kmDriver");

	return IoCreateDriver(&name, &driver_main);
}