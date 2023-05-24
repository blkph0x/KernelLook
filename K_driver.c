#include <ntdef.h>
#include <ntddk.h>
#include <ntimage.h>
#include <wdm.h>
#include <windef.h>

#define NTOSKRNL_LIB
#pragma comment(lib, "Ntoskrnl.lib")

#define IOCTL_GET_PROCESS_IDS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GET_MODULES CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define MAX_PROCESS_INFO_COUNT 1000 // Maximum number of process info entries
#define MAX_MODULE_INFO_COUNT 1000  // Maximum number of module info entries

typedef struct _PEB_LDR_DATA {
    UCHAR Reserved1[8];
    PVOID Reserved2[3];
    LIST_ENTRY InLoadOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _PEB
{
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PPEB_LDR_DATA Ldr;
    // other fields...
} PEB, * PPEB;
typedef struct _PROCESS_INFO {
    HANDLE ProcessId;
    WCHAR Name[MAX_PATH];
} PROCESS_INFO, * PPROCESS_INFO;

typedef struct _MODULE_INFO {
    PVOID Base;
    ULONG Size;
    WCHAR Name[MAX_PATH];
} MODULE_INFO, * PMODULE_INFO;
typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemProcessInformation = 5
} SYSTEM_INFORMATION_CLASS;

extern NTSTATUS PsLookupProcessByProcessId(
    IN HANDLE ProcessId,
    OUT PEPROCESS* Process
);

extern NTSTATUS ZwQuerySystemInformation(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    OUT PVOID SystemInformation,
    IN ULONG SystemInformationLength,
    OUT PULONG ReturnLength
);

extern PVOID PsGetProcessWow64Process(
    IN PEPROCESS Process
);

typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER Reserved[3];
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE ProcessId;
    HANDLE InheritedFromProcessId;
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    PVOID Reserved1[2];
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    PVOID Reserved2[3];
    UNICODE_STRING FullDllName;
    ULONG Reserved3[8];
    PVOID Reserved4[3];
    LIST_ENTRY InMemoryOrderLinks;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

// Logging macros
#define LogFunctionEntry() DbgPrint("[%s] Entering: %s\n", __FUNCTION__, __FUNCTION__)
#define LogFunctionExit() DbgPrint("[%s] Exiting: %s\n", __FUNCTION__, __FUNCTION__)
#define LogMessage(format, ...) DbgPrint("[%s] " format "\n", __FUNCTION__, __VA_ARGS__)

NTSTATUS GetProcessIds(PPROCESS_INFO ProcessInfo, ULONG ProcessInfoCount, PULONG ReturnLength)
{
    LogFunctionEntry();

    PVOID processInfoBuffer = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG bufferSize = 0;
    ULONG actualCount = 0;

    // Get size of the information to be gathered.
    status = ZwQuerySystemInformation(SystemProcessInformation, NULL, 0, &bufferSize);
    if (status != STATUS_INFO_LENGTH_MISMATCH)
    {
        LogMessage("Failed to get process information size. Error: 0x%X", status);
        return status;
    }

    // Allocate memory for the buffer.
    processInfoBuffer = ExAllocatePoolWithTag(NonPagedPool, bufferSize, 'Proc');
    if (processInfoBuffer == NULL)
    {
        LogMessage("Failed to allocate memory for process information");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Get the system information.
    status = ZwQuerySystemInformation(SystemProcessInformation, processInfoBuffer, bufferSize, NULL);
    if (!NT_SUCCESS(status))
    {
        LogMessage("Failed to query system information. Error: 0x%X", status);
        ExFreePool(processInfoBuffer);
        return status;
    }

    PSYSTEM_PROCESS_INFORMATION processInfo = (PSYSTEM_PROCESS_INFORMATION)processInfoBuffer;
    while (actualCount < ProcessInfoCount)
    {
        ProcessInfo[actualCount].ProcessId = processInfo->ProcessId;
        RtlCopyMemory(ProcessInfo[actualCount].Name, processInfo->ImageName.Buffer, processInfo->ImageName.Length);
        ProcessInfo[actualCount].Name[processInfo->ImageName.Length / sizeof(WCHAR)] = UNICODE_NULL;

        actualCount++;

        if (processInfo->NextEntryOffset == 0)
        {
            break;
        }

        processInfo = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)processInfo + processInfo->NextEntryOffset);
    }

    *ReturnLength = actualCount * sizeof(PROCESS_INFO);

    ExFreePool(processInfoBuffer);

    LogFunctionExit();
    return status;
}

NTSTATUS GetLoadedModules(HANDLE ProcessId, PMODULE_INFO ModuleInfo, ULONG ModuleInfoCount, PULONG ReturnLength)
{
    LogFunctionEntry();

    PEPROCESS process = NULL;
    PPEB peb = NULL;
    PLIST_ENTRY listEntry = NULL;
    PLDR_DATA_TABLE_ENTRY ldrEntry = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG actualCount = 0;

    // Retrieve the process object.
    status = PsLookupProcessByProcessId(ProcessId, &process);
    if (!NT_SUCCESS(status))
    {
        LogMessage("Failed to lookup process by process ID. Error: 0x%X", status);
        return status;
    }

    // Retrieve the PEB address.
    peb = (PPEB)PsGetProcessWow64Process(process);
    if (peb == NULL)
    {
        LogMessage("Failed to retrieve process PEB");
        ObDereferenceObject(process);
        return STATUS_UNSUCCESSFUL;
    }

    // Retrieve the first module.
    listEntry = peb->Ldr->InLoadOrderModuleList.Flink;
    ldrEntry = CONTAINING_RECORD(listEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
    while (actualCount < ModuleInfoCount)
    {
        ProbeForRead(ldrEntry, sizeof(LDR_DATA_TABLE_ENTRY), 1);

        ModuleInfo[actualCount].Base = ldrEntry->DllBase;
        ModuleInfo[actualCount].Size = ldrEntry->SizeOfImage;
        RtlCopyMemory(ModuleInfo[actualCount].Name, ldrEntry->FullDllName.Buffer, ldrEntry->FullDllName.Length);
        ModuleInfo[actualCount].Name[ldrEntry->FullDllName.Length / sizeof(WCHAR)] = UNICODE_NULL;

        actualCount++;

        if (listEntry == peb->Ldr->InLoadOrderModuleList.Blink)
        {
            break;
        }

        listEntry = listEntry->Flink;
        ldrEntry = CONTAINING_RECORD(listEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
    }

    *ReturnLength = actualCount * sizeof(MODULE_INFO);

    ObDereferenceObject(process);

    LogFunctionExit();
    return status;
}

NTSTATUS DispatchCreateClose(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
{
    LogFunctionEntry();

    UNREFERENCED_PARAMETER(pDeviceObject);

    pIrp->IoStatus.Status = STATUS_SUCCESS;
    pIrp->IoStatus.Information = 0;

    // Check if the IRP is being canceled
    if (pIrp->Cancel)
    {
        pIrp->IoStatus.Status = STATUS_CANCELLED;
        IoCompleteRequest(pIrp, IO_NO_INCREMENT);
        return STATUS_CANCELLED;
    }

    IoCompleteRequest(pIrp, IO_NO_INCREMENT);

    LogFunctionExit();
    return STATUS_SUCCESS;
}

NTSTATUS DispatchIoctl(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
{
    LogFunctionEntry();

    UNREFERENCED_PARAMETER(pDeviceObject);

    PIO_STACK_LOCATION pIoStackLocation = IoGetCurrentIrpStackLocation(pIrp);
    ULONG controlCode = pIoStackLocation->Parameters.DeviceIoControl.IoControlCode;

    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG returnLength = 0;

    if (controlCode == IOCTL_GET_PROCESS_IDS)
    {
        if (pIoStackLocation->Parameters.DeviceIoControl.OutputBufferLength < sizeof(PROCESS_INFO))
        {
            LogMessage("Insufficient buffer size for process info");
            status = STATUS_BUFFER_TOO_SMALL;
            goto Exit;
        }

        PPROCESS_INFO processInfo = (PPROCESS_INFO)pIrp->AssociatedIrp.SystemBuffer;
        ULONG processInfoCount = pIoStackLocation->Parameters.DeviceIoControl.OutputBufferLength / sizeof(PROCESS_INFO);

        status = GetProcessIds(processInfo, processInfoCount, &returnLength);
        if (status == STATUS_INFO_LENGTH_MISMATCH)
        {
            LogMessage("Insufficient buffer size for process info");
            status = STATUS_BUFFER_TOO_SMALL;
        }
    }
    else if (controlCode == IOCTL_GET_MODULES)
    {
        if (pIoStackLocation->Parameters.DeviceIoControl.InputBufferLength < sizeof(HANDLE) || pIoStackLocation->Parameters.DeviceIoControl.OutputBufferLength < sizeof(MODULE_INFO))
        {
            LogMessage("Insufficient buffer size for module info");
            status = STATUS_BUFFER_TOO_SMALL;
            goto Exit;
        }

        PHANDLE pProcessId = (PHANDLE)pIrp->AssociatedIrp.SystemBuffer;
        PMODULE_INFO moduleInfo = (PMODULE_INFO)((PUCHAR)pIrp->AssociatedIrp.SystemBuffer + sizeof(HANDLE));
        ULONG moduleInfoCount = (pIoStackLocation->Parameters.DeviceIoControl.OutputBufferLength - sizeof(HANDLE)) / sizeof(MODULE_INFO);

        // Validate the process ID
        PEPROCESS process = NULL;
        status = PsLookupProcessByProcessId(*pProcessId, &process);
        if (!NT_SUCCESS(status))
        {
            // Invalid process ID
            LogMessage("Invalid process ID");
            status = STATUS_INVALID_PARAMETER;
            goto Exit;
        }

        ObDereferenceObject(process);

        status = GetLoadedModules(*pProcessId, moduleInfo, moduleInfoCount, &returnLength);
        if (status == STATUS_INFO_LENGTH_MISMATCH)
        {
            LogMessage("Insufficient buffer size for module info");
            status = STATUS_BUFFER_TOO_SMALL;
        }
    }

Exit:
    pIrp->IoStatus.Status = status;
    pIrp->IoStatus.Information = returnLength;
    IoCompleteRequest(pIrp, IO_NO_INCREMENT);

    LogFunctionExit();
    return status;
}

VOID DriverUnload(PDRIVER_OBJECT pDriverObject)
{
    LogFunctionEntry();

    UNICODE_STRING dosDeviceName;
    RtlInitUnicodeString(&dosDeviceName, L"\\DosDevices\\ModuleList");
    IoDeleteSymbolicLink(&dosDeviceName);
    IoDeleteDevice(pDriverObject->DeviceObject);

    LogFunctionExit();
}

extern NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath)
{
    LogFunctionEntry();

    UNREFERENCED_PARAMETER(pRegistryPath);

    NTSTATUS status;

    // Set up dispatch routines
    pDriverObject->MajorFunction[IRP_MJ_CREATE] = DispatchCreateClose;
    pDriverObject->MajorFunction[IRP_MJ_CLOSE] = DispatchCreateClose;
    pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoctl;
    pDriverObject->DriverUnload = DriverUnload;

    // Create a device object
    UNICODE_STRING deviceName;
    RtlInitUnicodeString(&deviceName, L"\\Device\\ModuleList");
    PDEVICE_OBJECT pDeviceObject;
    status = IoCreateDevice(pDriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &pDeviceObject);
    if (!NT_SUCCESS(status))
    {
        LogMessage("Failed to create device. Error: 0x%X", status);
        return status;
    }

    // Create a symbolic link
    UNICODE_STRING dosDeviceName;
    RtlInitUnicodeString(&dosDeviceName, L"\\DosDevices\\ModuleList");
    status = IoCreateSymbolicLink(&dosDeviceName, &deviceName);
    if (!NT_SUCCESS(status))
    {
        LogMessage("Failed to create symbolic link. Error: 0x%X", status);
        IoDeleteDevice(pDeviceObject);
        return status;
    }

    LogFunctionExit();
    return STATUS_SUCCESS;
}
