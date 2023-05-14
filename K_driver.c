#include <ntdef.h>
#include <ntifs.h>
#include <ntstrsafe.h>
#include <ntddk.h>
#include <ntimage.h>
#include <wdm.h>
#include <windef.h>

#define NTSTRSAFE_LIB
#define NTOSKRNL_LIB
#pragma comment(lib, "Ntoskrnl.lib")



#define IOCTL_TRIGGER_FLAG_SEARCH CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_READ_MEMORY_OFFSET CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_DUMP_LOADED_MODULES CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_READ_ACCESS)

#define DEVICE_NAME L"\\Device\\MyMemoryReader"
#define SYMBOLIC_LINK_NAME L"\\DosDevices\\MyMemoryReader"

NTKERNELAPI
NTSTATUS
MmCopyVirtualMemory(
    _In_ PEPROCESS SourceProcess,
    _In_ PVOID SourceAddress,
    _In_ PEPROCESS TargetProcess,
    _Out_ PVOID TargetAddress,
    _In_ SIZE_T BufferSize,
    _In_ KPROCESSOR_MODE RequestorMode,
    _Out_ PSIZE_T NumberOfBytesCopied
);

typedef struct _FLAG_SEARCH_REQUEST {
    PVOID SearchValue;
    SIZE_T SearchSize;
    PVOID ResultAddress;
} FLAG_SEARCH_REQUEST, * PFLAG_SEARCH_REQUEST;

typedef struct _READ_MEMORY_REQUEST {
    PVOID SourceAddress;
    PVOID DestinationBuffer;
    SIZE_T Size;
} READ_MEMORY_REQUEST, * PREAD_MEMORY_REQUEST;
typedef struct _MODULE_INFO {
    PVOID BaseAddress;
    ULONG Size;
    CHAR ModuleName[256];
} MODULE_INFO, * PMODULE_INFO;
typedef struct _DUMP_MODULES_REQUEST {
    PMODULE_INFO ModulesBuffer;
    ULONG BufferLength;
    ULONG ModulesCount;
} DUMP_MODULES_REQUEST, * PDUMP_MODULES_REQUEST;

typedef struct _MY_DEVICE_EXTENSION {
    PDEVICE_OBJECT DeviceObject;
} MY_DEVICE_EXTENSION, * PMY_DEVICE_EXTENSION;
typedef struct _PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

#ifdef _WIN64
typedef struct _PEB {
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    BOOLEAN BitField;
    PVOID Mutant;
    PVOID ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
    PVOID ProcessParameters;
    PVOID SubSystemData;
    PVOID ProcessHeap;
} PEB, * PPEB;
#else
typedef struct _PEB {
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    PVOID Mutant;
    PVOID ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
    PVOID ProcessParameters;
    PVOID SubSystemData;
    PVOID ProcessHeap;
    PVOID FastPebLock;
    PVOID AtlThunkSListPtr;
    PVOID IFEOKey;
    PVOID CrossProcessFlags;
    PVOID KernelCallbackTable;
    PVOID SystemReserved;
    PVOID AtlThunkSListPtr32;
    PVOID ApiSetMap;
} PEB, * PPEB;
#endif

NTKERNELAPI
PPEB
PsGetProcessPeb(
    _In_ PEPROCESS Process
);

NTKERNELAPI
PVOID
PsGetProcessWow64Process(
    _In_ PEPROCESS Process
);

NTSTATUS
ZwProtectVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID* BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG NewProtect,
    _Out_ PULONG OldProtect
);

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath
);

NTSTATUS MyCreate(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
);

NTSTATUS MyClose(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
);

NTSTATUS MyDeviceControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
);

VOID MyDriverUnload(
    _In_ PDRIVER_OBJECT DriverObject
);

NTSTATUS
ReadMemoryOffset(
    _In_ HANDLE ProcessHandle,
    _In_ PVOID SourceAddress,
    _In_ PVOID DestinationBuffer,
    _In_ SIZE_T Size
);

NTSTATUS ScanHeap(
    _In_ HANDLE ProcessHandle,
    _In_ PVOID SearchValue,
    _In_ SIZE_T SearchSize,
    _Out_ PVOID* ResultAddress
);

NTSTATUS GetLoadedModules(
    _In_ HANDLE ProcessHandle,
    _Out_ PMODULE_INFO ModulesBuffer,
    _In_ ULONG BufferLength,
    _Out_ PULONG ModulesCount
);

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    (VOID)ZwProtectVirtualMemory;
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS status = STATUS_SUCCESS;
    PDEVICE_OBJECT deviceObject = NULL;
    UNICODE_STRING deviceName = RTL_CONSTANT_STRING(DEVICE_NAME);
    UNICODE_STRING symbolicLinkName = RTL_CONSTANT_STRING(SYMBOLIC_LINK_NAME);

    // Create the device object
    status = IoCreateDevice(DriverObject, sizeof(MY_DEVICE_EXTENSION), &deviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &deviceObject);
    if (!NT_SUCCESS(status)) {
        KdPrint(("Failed to create device object. Status: 0x%X\n", status));
        return status;
    }
    // Set up the device extension
    PMY_DEVICE_EXTENSION deviceExtension = (PMY_DEVICE_EXTENSION)deviceObject->DeviceExtension;
    deviceExtension->DeviceObject = deviceObject;

    // Create the symbolic link
    status = IoCreateSymbolicLink(&symbolicLinkName, &deviceName);
    if (!NT_SUCCESS(status)) {
        KdPrint(("Failed to create symbolic link. Status: 0x%X\n", status));
        IoDeleteDevice(deviceObject);
        return status;
    }

    // Set up the driver object
    DriverObject->DriverUnload = MyDriverUnload;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = MyCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = MyClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = MyDeviceControl;

    return status;
}

NTSTATUS MyCreate(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

NTSTATUS MyClose(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

NTSTATUS MyDeviceControl(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    NTSTATUS status = STATUS_SUCCESS;
    PIO_STACK_LOCATION ioStackLocation = IoGetCurrentIrpStackLocation(Irp);
    ULONG ioControlCode = ioStackLocation->Parameters.DeviceIoControl.IoControlCode;
    HANDLE processHandle = PsGetCurrentProcessId(); // Default to the current process ID

    if (ioControlCode != IOCTL_DUMP_LOADED_MODULES)
    {
        PVOID inputBuffer = Irp->AssociatedIrp.SystemBuffer;
        ULONG inputBufferLength = ioStackLocation->Parameters.DeviceIoControl.InputBufferLength;
        if (inputBuffer != NULL && inputBufferLength >= sizeof(HANDLE))
        {
            processHandle = *(PHANDLE)inputBuffer;
        }
    }

    switch (ioControlCode) {
    case IOCTL_TRIGGER_FLAG_SEARCH:
    {
        PFLAG_SEARCH_REQUEST flagSearchRequest = (PFLAG_SEARCH_REQUEST)Irp->AssociatedIrp.SystemBuffer;
        status = ScanHeap(PsGetCurrentProcessId(), flagSearchRequest->SearchValue, flagSearchRequest->SearchSize, &flagSearchRequest->ResultAddress);

        if (NT_SUCCESS(status)) {
            Irp->IoStatus.Information = sizeof(FLAG_SEARCH_REQUEST);
        }
    }
    break;
    case IOCTL_READ_MEMORY_OFFSET:
    {
        PREAD_MEMORY_REQUEST readMemoryRequest = (PREAD_MEMORY_REQUEST)Irp->AssociatedIrp.SystemBuffer;
        status = ReadMemoryOffset(PsGetCurrentProcessId(), readMemoryRequest->SourceAddress, readMemoryRequest->DestinationBuffer, readMemoryRequest->Size);

        if (NT_SUCCESS(status)) {
            Irp->IoStatus.Information = sizeof(READ_MEMORY_REQUEST);
        }
    }
    break;
    case IOCTL_DUMP_LOADED_MODULES:
    {
        PDUMP_MODULES_REQUEST dumpModulesRequest = (PDUMP_MODULES_REQUEST)Irp->AssociatedIrp.SystemBuffer;
        status = GetLoadedModules(PsGetCurrentProcessId(), dumpModulesRequest->ModulesBuffer, dumpModulesRequest->BufferLength, &dumpModulesRequest->ModulesCount);

        if (NT_SUCCESS(status)) {
            Irp->IoStatus.Information = sizeof(DUMP_MODULES_REQUEST);
        }
    }
    break;
    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}
VOID MyDriverUnload(_In_ PDRIVER_OBJECT DriverObject) {
    UNICODE_STRING symbolicLinkName = RTL_CONSTANT_STRING(SYMBOLIC_LINK_NAME);
    IoDeleteSymbolicLink(&symbolicLinkName);
    IoDeleteDevice(DriverObject->DeviceObject);
}

NTSTATUS
ReadMemoryOffset(
    _In_ HANDLE ProcessHandle,
    _In_ PVOID SourceAddress,
    _In_ PVOID DestinationBuffer,
    _In_ SIZE_T Size
)
{
    NTSTATUS status = STATUS_SUCCESS;
    
    PEPROCESS sourceProcess;
    PEPROCESS targetProcess;
    
    status = PsLookupProcessByProcessId(ProcessHandle, &sourceProcess);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("Failed to find process by ID. Status: 0x%X\n", status));
        return status;
    }

    targetProcess = PsGetCurrentProcess();

    SIZE_T numberOfBytesCopied = 0;
    status = MmCopyVirtualMemory(sourceProcess, SourceAddress, targetProcess, DestinationBuffer, Size, KernelMode, &numberOfBytesCopied);
    if (!NT_SUCCESS(status))
    {
        KdPrint(("Failed to copy virtual memory. Status: 0x%X\n", status));
    }

    ObDereferenceObject(sourceProcess);
    return status;
}

NTSTATUS ScanHeap(
    _In_ HANDLE ProcessHandle,
    _In_ PVOID SearchValue,
    _In_ SIZE_T SearchSize,
    _Out_ PVOID* ResultAddress
)
{
    NTSTATUS status = STATUS_SUCCESS;
    
    PEPROCESS process;
    ULONG_PTR startAddress, endAddress;
    status = PsLookupProcessByProcessId(ProcessHandle, &process);
    *ResultAddress = NULL;

    status = PsLookupProcessByProcessId(ProcessHandle, &process);
    if (!NT_SUCCESS(status)) {
        KdPrint(("Failed to find process by ID. Status: 0x%X\n", status));
        return status;
    }

    startAddress = (ULONG_PTR)MM_LOWEST_USER_ADDRESS;
    endAddress = (ULONG_PTR)MM_HIGHEST_USER_ADDRESS;

    for (ULONG_PTR address = startAddress; address < endAddress; address += PAGE_SIZE) {
        MEMORY_BASIC_INFORMATION mbi;

        status = ZwQueryVirtualMemory(ProcessHandle, (PVOID)address, MemoryBasicInformation, &mbi, sizeof(mbi), NULL);
        if (!NT_SUCCESS(status)) {
            continue;
        }

        if (mbi.State != MEM_COMMIT || mbi.Protect == PAGE_NOACCESS || mbi.Protect & PAGE_GUARD) {
            address = (ULONG_PTR)mbi.BaseAddress + mbi.RegionSize;
            continue;
        }

        //SIZE_T bytesRead = 0;
        UCHAR buffer[PAGE_SIZE];

        status = ReadMemoryOffset(ProcessHandle, (PVOID)address, buffer, PAGE_SIZE);
        if (NT_SUCCESS(status)) {
            for (SIZE_T i = 0; i < PAGE_SIZE - SearchSize; i++) {
                if (RtlCompareMemory(buffer + i, SearchValue, SearchSize) == SearchSize) {
                    *ResultAddress = (PVOID)(address + i);
                    ObDereferenceObject(process);

                    return STATUS_SUCCESS;
                }
            }
        }

        address += PAGE_SIZE;
    }

    ObDereferenceObject(process);
    return STATUS_NOT_FOUND;
}
NTSTATUS GetLoadedModules(
    _In_ HANDLE ProcessHandle,
    _Out_ PMODULE_INFO ModulesBuffer,
    _In_ ULONG BufferLength,
    _Out_ PULONG ModulesCount
)
{
    NTSTATUS status;
    //ULONG bytesNeeded;
    PPEB_LDR_DATA ldrData;
    PLIST_ENTRY head, current;
    PLDR_DATA_TABLE_ENTRY ldrEntry;
    PMODULE_INFO currentModule;
    ULONG currentModuleCount = 0;

    PEPROCESS process;
    status = PsLookupProcessByProcessId(ProcessHandle, &process);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    PEPROCESS currentProcess = PsGetCurrentProcess();
    PPEB peb = PsGetProcessPeb(currentProcess);
#ifdef _WIN64
    typedef struct _PEB32 {
        BOOLEAN InheritedAddressSpace;
        BOOLEAN ReadImageFileExecOptions;
        BOOLEAN BeingDebugged;
        BOOLEAN BitField;
        PVOID Mutant;
        PVOID ImageBaseAddress;
        PVOID Ldr;
        PVOID ProcessParameters;
        PVOID SubSystemData;
        PVOID ProcessHeap;
        PVOID FastPebLock;
        PVOID AtlThunkSListPtr;
        PVOID IFEOKey;
        PVOID CrossProcessFlags;
        PVOID KernelCallbackTable;
        ULONG SystemReserved;
        ULONG AtlThunkSListPtr32;
        PVOID ApiSetMap;
    } PEB32, * PPEB32;
#endif

    ldrData = peb->Ldr;

    head = &ldrData->InLoadOrderModuleList;
    current = head->Flink;

    while (current != head) {
        ldrEntry = CONTAINING_RECORD(current, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

        status = ReadMemoryOffset(ProcessHandle, ldrEntry, &ldrEntry, sizeof(LDR_DATA_TABLE_ENTRY));
        if (!NT_SUCCESS(status)) {
            ObDereferenceObject(process);
            return status;
        }

        if (currentModuleCount * sizeof(MODULE_INFO) < BufferLength) {
            currentModule = &ModulesBuffer[currentModuleCount];
            currentModule->BaseAddress = ldrEntry->DllBase;
            currentModule->Size = ldrEntry->SizeOfImage;
            status = ReadMemoryOffset(ProcessHandle, ldrEntry->BaseDllName.Buffer, currentModule->ModuleName, ldrEntry->BaseDllName.Length);
            if (!NT_SUCCESS(status)) {
                ObDereferenceObject(process);
                return status;
            }
            currentModule->ModuleName[ldrEntry->BaseDllName.Length / sizeof(WCHAR)] = L'\0';
        }

        currentModuleCount++;
        current = current->Flink;
    }

    *ModulesCount = currentModuleCount;
    ObDereferenceObject(process);
    return STATUS_SUCCESS;
}
