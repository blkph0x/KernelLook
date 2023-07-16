#include <ntdef.h>
#include <ntddk.h>
#include <ntimage.h>
#include <wdm.h>
#include <windef.h>
#include <ntstrsafe.h>
#define NTOSKRNL_LIB
#pragma comment(lib, "Ntoskrnl.lib")

#define IOCTL_GET_PROCESS_IDS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_GET_MODULES CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_READ_ACCESS)

#define MAX_PROCESS_INFO_COUNT 80000 // Maximum number of process info entries
#define MAX_MODULE_INFO_COUNT 80000  // Maximum number of module info entries
#define MAX_PATH 260

typedef struct _PROCESS_INFO {
    HANDLE ProcessId;
    WCHAR Name[MAX_PATH];
} PROCESS_INFO, * PPROCESS_INFO;

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

extern NTSTATUS NtQuerySystemInformation(
    IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
    OUT PVOID SystemInformation,
    IN ULONG SystemInformationLength,
    OUT PULONG ReturnLength
);

extern PVOID PsGetProcessWow64Process(
    IN PEPROCESS Process
);

extern NTSTATUS NTAPI ZwQuerySystemInformation(
    IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
    OUT PVOID SystemInformation,
    IN ULONG SystemInformationLength,
    OUT PULONG ReturnLength OPTIONAL
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

    NTSTATUS status = STATUS_SUCCESS;
    ULONG bufferSize = 0;
    ULONG actualCount = 0;

    // Determine the required buffer size
    status = NtQuerySystemInformation(SystemProcessInformation, NULL, 0, &bufferSize);
    if (status != STATUS_INFO_LENGTH_MISMATCH)
    {
        LogMessage("Failed to get process information size. Error: 0x%X", status);
        return status;
    }
    // Log the returned buffer size
    DbgPrint("Returned buffer size after first call: %lu\n", bufferSize);

    LogMessage("Obtained required process info size: %lu", bufferSize);


    // Allocate memory for the buffer
    PVOID processInfoBuffer = ExAllocatePoolWithTag(NonPagedPool, bufferSize, 'Proc');
    if (processInfoBuffer == NULL)
    {
        LogMessage("Failed to allocate memory for process information");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    LogMessage("Successfully allocated memory for process info");

    // Retrieve the process information
    status = NtQuerySystemInformation(SystemProcessInformation, processInfoBuffer, bufferSize, &bufferSize);
    if (!NT_SUCCESS(status))
    {
        LogMessage("Failed to get process info. Error: 0x%X", status);
        ExFreePool(processInfoBuffer);
        return status;
    }

    // Traverse the process information and copy to the output buffer
    PSYSTEM_PROCESS_INFORMATION currentProcessInfo = (PSYSTEM_PROCESS_INFORMATION)processInfoBuffer;
    while (currentProcessInfo != NULL && actualCount < ProcessInfoCount)
    {
        ProcessInfo[actualCount].ProcessId = currentProcessInfo->ProcessId;
        RtlCopyMemory(ProcessInfo[actualCount].Name, currentProcessInfo->ImageName.Buffer, currentProcessInfo->ImageName.Length);
        ProcessInfo[actualCount].Name[currentProcessInfo->ImageName.Length / sizeof(WCHAR)] = UNICODE_NULL;

        LogMessage("Copied process info: ProcessId=%lu, Name=%ls", ProcessInfo[actualCount].ProcessId, ProcessInfo[actualCount].Name);

        actualCount++;

        if (currentProcessInfo->NextEntryOffset == 0)
            break;

        currentProcessInfo = (PSYSTEM_PROCESS_INFORMATION)((PBYTE)currentProcessInfo + currentProcessInfo->NextEntryOffset);
    }

    *ReturnLength = actualCount * sizeof(PROCESS_INFO);

    ExFreePool(processInfoBuffer);

    LogMessage("Completed process info retrieval");

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

        LogMessage("Copied module info: Base=%p, Size=%lu, Name=%ls", ModuleInfo[actualCount].Base, ModuleInfo[actualCount].Size, ModuleInfo[actualCount].Name);

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
        LogMessage("Input Buffer Length for IOCTL_GET_PROCESS_IDS: %lu", pIoStackLocation->Parameters.DeviceIoControl.InputBufferLength);
        LogMessage("Output Buffer Length for IOCTL_GET_PROCESS_IDS: %lu", pIoStackLocation->Parameters.DeviceIoControl.OutputBufferLength);

        if (pIoStackLocation->Parameters.DeviceIoControl.OutputBufferLength < sizeof(PROCESS_INFO))
        {
            LogMessage("Insufficient buffer size for process info");
            status = STATUS_BUFFER_TOO_SMALL;
            goto Exit;
        }
        LogMessage("Input Buffer Length for IOCTL_GET_PROCESS_IDS: %lu", pIoStackLocation->Parameters.DeviceIoControl.InputBufferLength);
        LogMessage("Output Buffer Length for IOCTL_GET_PROCESS_IDS: %lu", pIoStackLocation->Parameters.DeviceIoControl.OutputBufferLength);
        PPROCESS_INFO processInfo = (PPROCESS_INFO)pIrp->AssociatedIrp.SystemBuffer;
        ULONG processInfoCount = pIoStackLocation->Parameters.DeviceIoControl.OutputBufferLength / sizeof(PROCESS_INFO);

        status = GetProcessIds(processInfo, processInfoCount, &returnLength);
        if (status == STATUS_INFO_LENGTH_MISMATCH)
        {
            LogMessage("Insufficient buffer size for process info");
            status = STATUS_BUFFER_TOO_SMALL;
        }
        LogMessage("Input Buffer Length for IOCTL_GET_PROCESS_IDS: %lu", pIoStackLocation->Parameters.DeviceIoControl.InputBufferLength);
        LogMessage("Output Buffer Length for IOCTL_GET_PROCESS_IDS: %lu", pIoStackLocation->Parameters.DeviceIoControl.OutputBufferLength);
    }
    else if (controlCode == IOCTL_GET_MODULES)
    {
        LogMessage("Input Buffer Length for IOCTL_GET_MODULES: %lu", pIoStackLocation->Parameters.DeviceIoControl.InputBufferLength);
        LogMessage("Output Buffer Length for IOCTL_GET_MODULES: %lu", pIoStackLocation->Parameters.DeviceIoControl.OutputBufferLength);

        if (pIoStackLocation->Parameters.DeviceIoControl.InputBufferLength < sizeof(HANDLE) || pIoStackLocation->Parameters.DeviceIoControl.OutputBufferLength < sizeof(MODULE_INFO))
        {
            LogMessage("Insufficient buffer size for module info");
            status = STATUS_BUFFER_TOO_SMALL;
            goto Exit;
        }
        LogMessage("Input Buffer Length for IOCTL_GET_PROCESS_IDS: %lu", pIoStackLocation->Parameters.DeviceIoControl.InputBufferLength);
        LogMessage("Output Buffer Length for IOCTL_GET_PROCESS_IDS: %lu", pIoStackLocation->Parameters.DeviceIoControl.OutputBufferLength);
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
