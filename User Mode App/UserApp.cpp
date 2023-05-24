#include <Windows.h>
#include <stdio.h>

#define IOCTL_GET_PROCESS_IDS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GET_MODULES CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define MAX_PROCESS_INFO_COUNT 1000 // Maximum number of process info entries
#define MAX_MODULE_INFO_COUNT 1000  // Maximum number of module info entries

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
        printf("Failed to get process info. Error: %d\n", GetLastError());
        HeapFree(GetProcessHeap(), 0, pProcessInfo);
        CloseHandle(hDevice);
        return 1;
    }
    printf("Successfully obtained process info.\n");

    // Print process info
    printf("Process Info:\n");
    for (DWORD i = 0; i < bytesReturned / sizeof(PROCESS_INFO); i++)
    {
        printf("Process ID: %p, Name: %p\n", pProcessInfo[i].ProcessId, pProcessInfo[i].Name);
    }
    printf("\n");

    // Prompt user to enter a process ID for module info
    printf("Enter a process ID to get module info: ");
    HANDLE processId = 0;
    scanf_s("%p", &processId);

    // Prepare input buffer with process ID
    BYTE inputBuffer[sizeof(HANDLE)] = { 0 };
    *(PHANDLE)inputBuffer = (HANDLE)processId;

    // Get the required buffer size for module info
    ULONG moduleInfoSize = 0;
    if (!DeviceIoControl(hDevice, IOCTL_GET_MODULES, inputBuffer, sizeof(HANDLE), NULL, 0, &bytesReturned, NULL))
    {
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
        {
            printf("Failed to get module info size. Error: %d\n", GetLastError());
            HeapFree(GetProcessHeap(), 0, pProcessInfo);
            CloseHandle(hDevice);
            return 1;
        }
        printf("Obtained required module info size.\n");

        moduleInfoSize = bytesReturned;
    }

    // Allocate memory for module info
    PMODULE_INFO pModuleInfo = (PMODULE_INFO)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, moduleInfoSize);
    if (pModuleInfo == NULL)
    {
        printf("Failed to allocate memory for module info.\n");
        HeapFree(GetProcessHeap(), 0, pProcessInfo);
        CloseHandle(hDevice);
        return 1;
    }
    printf("Successfully allocated memory for module info.\n");

    // Get module info
    if (!DeviceIoControl(hDevice, IOCTL_GET_MODULES, inputBuffer, sizeof(HANDLE), pModuleInfo, moduleInfoSize, &bytesReturned, NULL))
    {
        printf("Failed to get module info. Error: %d\n", GetLastError());
        HeapFree(GetProcessHeap(), 0, pModuleInfo);
        HeapFree(GetProcessHeap(), 0, pProcessInfo);
        CloseHandle(hDevice);
        return 1;
    }
    printf("Successfully obtained module info.\n");

    // Print module info
    printf("Module Info:\n");
    for (DWORD i = 0; i < bytesReturned / sizeof(MODULE_INFO); i++)
    {
        printf("Base Address: %p, Size: %lu, Name: %ls\n", pModuleInfo[i].Base, pModuleInfo[i].Size, pModuleInfo[i].Name);
    }

    // Clean up resources
    HeapFree(GetProcessHeap(), 0, pModuleInfo);
    HeapFree(GetProcessHeap(), 0, pProcessInfo);
    CloseHandle(hDevice);
    printf("Cleaned up resources and closing the application.\n");

    return 0;
}
