#include <iostream>
#include <vector>
#include <Windows.h>

#define IOCTL_GET_PROCESS_IDS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GET_MODULES CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

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
    HANDLE hDevice = CreateFile(L"\\\\.\\ModuleList", GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

    if (hDevice == INVALID_HANDLE_VALUE) {
        std::cout << "Failed to open device. Error: " << GetLastError() << std::endl;
        return 1;
    }

    DWORD bytesReturned = 0;
    std::vector<PROCESS_INFO> processInfo(256);
    BOOL result = DeviceIoControl(hDevice, IOCTL_GET_PROCESS_IDS, nullptr, 0, processInfo.data(), processInfo.size() * sizeof(PROCESS_INFO), &bytesReturned, nullptr);

    if (!result) {
        std::cout << "Failed to get process ids. Error: " << GetLastError() << std::endl;
        CloseHandle(hDevice);
        return 1;
    }

    for (unsigned int i = 0; i < bytesReturned / sizeof(PROCESS_INFO); i++) {
        std::wcout << L"Process ID: " << processInfo[i].ProcessId << L", Name: " << processInfo[i].Name << std::endl;
    }

    std::cout << "Enter process id to get modules: ";
    ULONG processId;
    std::cin >> processId;

    std::vector<MODULE_INFO> moduleInfo(256);
    result = DeviceIoControl(hDevice, IOCTL_GET_MODULES, &processId, sizeof(processId), moduleInfo.data(), moduleInfo.size() * sizeof(MODULE_INFO), &bytesReturned, nullptr);

    if (!result) {
        std::cout << "Failed to get modules. Error: " << GetLastError() << std::endl;
        CloseHandle(hDevice);
        return 1;
    }

    for (unsigned int i = 0; i < bytesReturned / sizeof(MODULE_INFO); i++) {
        std::wcout << L"Module Base: " << moduleInfo[i].Base << L", Size: " << moduleInfo[i].Size << L", Name: " << moduleInfo[i].Name << std::endl;
    }

    CloseHandle(hDevice);
    return 0;
}
