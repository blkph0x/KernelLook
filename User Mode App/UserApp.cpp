#include <Windows.h>
#include <stdio.h>

#define IOCTL_GET_PROCESS_IDS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_GET_MODULES CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_READ_ACCESS)

#define MAX_PROCESS_INFO_COUNT 80000 // Maximum number of process info entries
#define MAX_MODULE_INFO_COUNT 80000  // Maximum number of module info entries

typedef struct _PROCESS_INFO {
    HANDLE ProcessId;
    WCHAR Name[MAX_PATH];
} PROCESS_INFO, * PPROCESS_INFO;

typedef struct _MODULE_INFO {
    PVOID Base;
    ULONG Size;
    WCHAR Name[MAX_PATH];
} MODULE_INFO, * PMODULE_INFO;

int main()
{
    HANDLE hDevice = INVALID_HANDLE_VALUE;
    DWORD bytesReturned = 0;

    // Open a handle to the driver device
    hDevice = CreateFile(L"\\\\.\\ModuleList", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hDevice == INVALID_HANDLE_VALUE)
    {
        printf("Failed to open device. Error: %d\n", GetLastError());
        return 1;
    }
    printf("Successfully opened the device.\n");

    // Get the required buffer size for process info
    ULONG processInfoSize = 0;
    if (!DeviceIoControl(hDevice, IOCTL_GET_PROCESS_IDS, NULL, 0, NULL, 0, &bytesReturned, NULL))
    {
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
        {
            printf("Failed to get process info size. Error: %d\n", GetLastError());
            CloseHandle(hDevice);
            return 1;
        }
        printf("Obtained required process info size.\n");

        processInfoSize = bytesReturned;
    }

    // Allocate memory for process info
    PPROCESS_INFO pProcessInfo = (PPROCESS_INFO)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, processInfoSize);
    if (pProcessInfo == NULL)
    {
        printf("Failed to allocate memory for process info.\n");
        CloseHandle(hDevice);
        return 1;
    }
    printf("Successfully allocated memory for process info.\n");

    // Get process info
    if (!DeviceIoControl(hDevice, IOCTL_GET_PROCESS_IDS, NULL, 0, pProcessInfo, processInfoSize, &bytesReturned, NULL))
    {
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
        {
            printf("Failed to get process info. Error: %d\n", GetLastError());
            HeapFree(GetProcessHeap(), 0, pProcessInfo);
            CloseHandle(hDevice);
            return 1;
        }
        printf("Insufficient buffer size for process info. Retry with a larger buffer.\n");

        // Adjust the buffer size and retry the call
        processInfoSize = bytesReturned;
        HeapFree(GetProcessHeap(), 0, pProcessInfo);
        pProcessInfo = (PPROCESS_INFO)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, processInfoSize);
        if (pProcessInfo == NULL)
        {
            printf("Failed to allocate memory for process info.\n");
            CloseHandle(hDevice);
            return 1;
        }

        if (!DeviceIoControl(hDevice, IOCTL_GET_PROCESS_IDS, NULL, 0, pProcessInfo, processInfoSize, &bytesReturned, NULL))
        {
            printf("Failed to get process info. Error: %d\n", GetLastError());
            HeapFree(GetProcessHeap(), 0, pProcessInfo);
            CloseHandle(hDevice);
            return 1;
        }

        printf("Successfully obtained process info after adjusting buffer size.\n");
    }
    else
    {
        printf("Successfully obtained process info.\n");
    }

    // Print process info
    printf("Process Info:\n");
    for (DWORD i = 0; i < bytesReturned / sizeof(PROCESS_INFO); i++)
    {
        printf("Process ID: %p, Name: %ls\n", pProcessInfo[i].ProcessId, pProcessInfo[i].Name);
    }
    printf("\n");

    // Clean up resources
    HeapFree(GetProcessHeap(), 0, pProcessInfo);
    CloseHandle(hDevice);
    printf("Cleaned up resources and closing the application.\n");

    return 0;
}
