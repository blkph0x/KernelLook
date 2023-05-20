#include <ntdef.h>
#include <ntddk.h>
#include <ntimage.h>
#include <wdm.h>
#include <windef.h>

#define NTOSKRNL_LIB
#pragma comment(lib, "Ntoskrnl.lib")

#define IOCTL_GET_PROCESS_IDS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GET_MODULES CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

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
    PVOID Reserved2[3];
    UNICODE_STRING FullDllName; // use FullDllName instead of BaseDllName
    ULONG Reserved3[8];
    PVOID Reserved4[3];
    LIST_ENTRY InMemoryOrderLinks;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

NTSTATUS GetProcessIds(PPROCESS_INFO ProcessInfo, ULONG ProcessInfoCount, PULONG ReturnLength)
{
    PVOID processInfoBuffer = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG bufferSize = 0;
    ULONG actualCount = 0;

    status = ZwQuerySystemInformation(SystemProcessInformation, NULL, 0, &bufferSize);
    if (status != STATUS_INFO_LENGTH_MISMATCH)
    {
        return status;
    }

    processInfoBuffer = ExAllocatePoolWithTag(NonPagedPool, bufferSize, 'Proc');
    if (processInfoBuffer == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = ZwQuerySystemInformation(SystemProcessInformation, processInfoBuffer, bufferSize, NULL);
    if (!NT_SUCCESS(status))
    {
        ExFreePool(processInfoBuffer);
        return status;
    }

    PSYSTEM_PROCESS_INFORMATION processInfo = (PSYSTEM_PROCESS_INFORMATION)processInfoBuffer;
    while (TRUE)
    {
        if (actualCount >= ProcessInfoCount)
        {
            status = STATUS_BUFFER_OVERFLOW;
            break;
        }

        __try
        {
            ProbeForWrite(&ProcessInfo[actualCount], sizeof(PROCESS_INFO), sizeof(ULONG_PTR));
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            status = GetExceptionCode();
            break;
        }

        RtlCopyMemory(ProcessInfo[actualCount].Name, processInfo->ImageName.Buffer, processInfo->ImageName.Length);
        ProcessInfo[actualCount].Name[processInfo->ImageName.Length / sizeof(WCHAR)] = UNICODE_NULL;




        actualCount++;

        if (processInfo->NextEntryOffset == 0)
        {
            break;
        }

        processInfo = (PSYSTEM_PROCESS_INFORMATION)((PCHAR)processInfo + processInfo->NextEntryOffset);
    }

    *ReturnLength = actualCount * sizeof(PROCESS_INFO);

    ExFreePool(processInfoBuffer);

    return status;
}

NTSTATUS GetLoadedModules(ULONG ProcessId, PMODULE_INFO ModuleInfo, ULONG ModuleInfoCount, PULONG ReturnLength)
{
    PEPROCESS Process = NULL;
    NTSTATUS Status = STATUS_SUCCESS;
    ULONG ActualCount = 0;

    // Get the EPROCESS structure of the target process
    Status = PsLookupProcessByProcessId((HANDLE)ProcessId, &Process);
    if (!NT_SUCCESS(Status))
    {
        Process = NULL; // Ensure Process is NULL on failure
        goto Cleanup;
    }

    // Validate the process ID
    if (!PsGetProcessWow64Process(Process))
    {
        Status = STATUS_INVALID_PARAMETER;
        goto Cleanup;
    }

    __try
    {
        PVOID Peb = PsGetProcessWow64Process(Process);
        if (Peb == NULL)
        {
            Status = STATUS_UNSUCCESSFUL;
            goto Cleanup;
        }

        PPEB_LDR_DATA LdrData = (PPEB_LDR_DATA)((PPEB)Peb)->Ldr;
        PLIST_ENTRY LdrList = LdrData->InLoadOrderModuleList.Flink;
        PLIST_ENTRY LastEntry = &LdrData->InLoadOrderModuleList;

        while (LdrList != LastEntry)
        {
            if (ActualCount >= ModuleInfoCount)
            {
                Status = STATUS_BUFFER_OVERFLOW;
                break;
            }

            PLDR_DATA_TABLE_ENTRY LdrEntry = CONTAINING_RECORD(LdrList, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

            // Validate ModuleInfo pointer
            __try
            {
                ProbeForWrite(ModuleInfo, sizeof(MODULE_INFO), sizeof(ULONG_PTR));
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                Status = GetExceptionCode();
                goto Cleanup;
            }

            ModuleInfo[ActualCount].Base = LdrEntry->DllBase;
            if (LdrEntry->Reserved3 != NULL) {
                ModuleInfo[ActualCount].Size = *(LdrEntry->Reserved3);
            }

            // Get the length to copy, ensuring it does not exceed the buffer size
            size_t nameLength = LdrEntry->FullDllName.Length;
            if (nameLength > (MAX_PATH - 1) * sizeof(WCHAR))
            {
                nameLength = (MAX_PATH - 1) * sizeof(WCHAR);
            }

            __try
            {
                RtlCopyMemory(ModuleInfo[ActualCount].Name, LdrEntry->FullDllName.Buffer, nameLength);
                ModuleInfo[ActualCount].Name[nameLength / sizeof(WCHAR)] = UNICODE_NULL;
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                Status = GetExceptionCode();
                goto Cleanup;
            }

            ActualCount++;
            LdrList = LdrList->Flink;
        }

        if (ActualCount > 0 && ActualCount < ModuleInfoCount)
        {
            Status = STATUS_BUFFER_OVERFLOW;
        }
    }
    __finally
    {
        if (Process != NULL)
        {
            ObDereferenceObject(Process);
        }
    }

Cleanup:
    if (NT_SUCCESS(Status))
    {
        *ReturnLength = ActualCount * sizeof(MODULE_INFO);
    }
    else
    {
        *ReturnLength = 0;
    }

    return Status;
}

NTSTATUS DispatchCreateClose(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
{
    UNREFERENCED_PARAMETER(pDeviceObject);

    pIrp->IoStatus.Status = STATUS_SUCCESS;
    pIrp->IoStatus.Information = 0;

    IoCompleteRequest(pIrp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

NTSTATUS DispatchIoctl(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
{
    UNREFERENCED_PARAMETER(pDeviceObject);

    PIO_STACK_LOCATION pIoStackLocation = IoGetCurrentIrpStackLocation(pIrp);
    ULONG controlCode = pIoStackLocation->Parameters.DeviceIoControl.IoControlCode;

    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG returnLength = 0;

    if (controlCode == IOCTL_GET_PROCESS_IDS)
    {
        // The output buffer is an array of PROCESS_INFO structures
        if (pIrp->MdlAddress == NULL || pIrp->MdlAddress->MappedSystemVa == NULL || pIoStackLocation->Parameters.DeviceIoControl.OutputBufferLength < sizeof(PROCESS_INFO))
        {
            status = STATUS_INVALID_PARAMETER;
            goto Exit;
        }

        PPROCESS_INFO processInfo = (PPROCESS_INFO)MmGetSystemAddressForMdlSafe(pIrp->MdlAddress, NormalPagePriority);
        if (processInfo == NULL)
        {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto Exit;
        }

        ULONG processInfoCount = pIoStackLocation->Parameters.DeviceIoControl.OutputBufferLength / sizeof(PROCESS_INFO);

        // Validate processInfoCount and processInfo
        if (processInfoCount == 0)
        {
            status = STATUS_INVALID_PARAMETER;
            goto Exit;
        }

        __try
        {
            // Get the process IDs
            status = GetProcessIds(processInfo, processInfoCount, &returnLength);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            status = GetExceptionCode();
        }

        if (!NT_SUCCESS(status))
        {
            goto Exit;
        }
    }
    else if (controlCode == IOCTL_GET_MODULES)
    {
        // The input buffer is the process ID
        if (pIrp->AssociatedIrp.SystemBuffer == NULL || pIoStackLocation->Parameters.DeviceIoControl.InputBufferLength < sizeof(ULONG))
        {
            status = STATUS_INVALID_PARAMETER;
            goto Exit;
        }

        // Probe for read the process ID buffer
        __try
        {
            ProbeForRead(pIrp->AssociatedIrp.SystemBuffer, sizeof(ULONG), sizeof(ULONG));
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            status = GetExceptionCode();
            goto Exit;
        }

        ULONG processId = *(ULONG*)pIrp->AssociatedIrp.SystemBuffer;

        // The output buffer is an array of MODULE_INFO structures
        if (pIrp->MdlAddress == NULL || pIrp->MdlAddress->MappedSystemVa == NULL || pIoStackLocation->Parameters.DeviceIoControl.OutputBufferLength < sizeof(MODULE_INFO))
        {
            status = STATUS_INVALID_PARAMETER;
            goto Exit;
        }

        PMODULE_INFO moduleInfo = (PMODULE_INFO)MmGetSystemAddressForMdlSafe(pIrp->MdlAddress, NormalPagePriority);
        if (moduleInfo == NULL)
        {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto Exit;
        }

        ULONG moduleInfoCount = pIoStackLocation->Parameters.DeviceIoControl.OutputBufferLength / sizeof(MODULE_INFO);

        // Validate moduleInfoCount and moduleInfo
        if (moduleInfoCount == 0)
        {
            status = STATUS_INVALID_PARAMETER;
            goto Exit;
        }

        __try
        {
            // Get the loaded modules of the process
            status = GetLoadedModules(processId, moduleInfo, moduleInfoCount, &returnLength);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            status = GetExceptionCode();
        }

        if (!NT_SUCCESS(status))
        {
            goto Exit;
        }
    }

    status = STATUS_SUCCESS;

Exit:
    pIrp->IoStatus.Status = status;
    pIrp->IoStatus.Information = returnLength;
    IoCompleteRequest(pIrp, IO_NO_INCREMENT);

    return status;
}

VOID DriverUnload(PDRIVER_OBJECT pDriverObject)
{
    UNICODE_STRING dosDeviceName;
    RtlInitUnicodeString(&dosDeviceName, L"\\DosDevices\\ModuleList");
    IoDeleteSymbolicLink(&dosDeviceName);
    IoDeleteDevice(pDriverObject->DeviceObject);
}

extern NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath)
{
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
        return status;
    }

    // Create a symbolic link
    UNICODE_STRING dosDeviceName;
    RtlInitUnicodeString(&dosDeviceName, L"\\DosDevices\\ModuleList");
    status = IoCreateSymbolicLink(&dosDeviceName, &deviceName);
    if (!NT_SUCCESS(status))
    {
        IoDeleteDevice(pDeviceObject);
        return status;
    }

    return STATUS_SUCCESS;
}
