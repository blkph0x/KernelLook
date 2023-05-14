#include <Windows.h>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <stdexcept>

constexpr auto IOCTL_TRIGGER_FLAG_SEARCH = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_READ_ACCESS);
constexpr auto IOCTL_READ_MEMORY_OFFSET = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_READ_ACCESS);
constexpr auto IOCTL_DUMP_LOADED_MODULES = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_READ_ACCESS);

struct FLAG_SEARCH_REQUEST {
    PVOID SearchValue;
    SIZE_T SearchSize;
    PVOID ResultAddress;
};

struct READ_MEMORY_REQUEST {
    PVOID SourceAddress;
    PVOID DestinationBuffer;
    SIZE_T Size;
};

struct MODULE_INFO {
    PVOID BaseAddress;
    ULONG Size;
    CHAR ModuleName[256];
};

struct DUMP_MODULES_REQUEST {
    MODULE_INFO* ModulesBuffer;
    ULONG BufferLength;
    ULONG ModulesCount;
};

void SaveToFile(const std::string& content, const std::string& filePath) {
    std::ofstream outputFile(filePath, std::ios::binary);
    outputFile.write(content.data(), content.size());
    outputFile.close();
}

void SaveModuleInfo(const std::vector<MODULE_INFO>& modules, const std::string& folderPath) {
    for (const auto& module : modules) {
        std::string moduleFileName = folderPath + "\\" + std::string(module.ModuleName) + ".bin";
        SaveToFile(std::string(reinterpret_cast<const char*>(module.BaseAddress), module.Size), moduleFileName);
    }
}

bool ExecuteIoctl(HANDLE hDevice, int ioctlCode, PVOID inputBuffer, DWORD inputSize, PVOID outputBuffer, DWORD outputSize, DWORD* bytesReturned) {
    return DeviceIoControl(hDevice, ioctlCode, inputBuffer, inputSize, outputBuffer, outputSize, bytesReturned, nullptr);
}

int main() {
    using PVOID = void*;
    using SIZE_T = size_t;
    using ULONG = unsigned long;
    using CHAR = char;

    std::string processName;
    std::cout << "Enter the process name: ";
    std::cin >> processName;

    int ioctlCode;
    std::cout << "Enter the IOCTL code (800, 801, or 802): ";
    std::cin >> ioctlCode;

    std::string ioctlDescription;
    PVOID inputBuffer = nullptr;
    DWORD inputSize = 0;
    PVOID outputBuffer = nullptr;
    DWORD outputSize = 0;
    HANDLE hDevice = CreateFile(L"\\\\.\\MyMemoryReader", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hDevice == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to open device. Error: " << GetLastError() << std::endl;
        return 1;
    }

    DWORD bytesReturned;
    if (!ExecuteIoctl(hDevice, ioctlCode, inputBuffer, inputSize, outputBuffer, outputSize, &bytesReturned)) {
        std::cerr << "Failed to execute IOCTL. Error: " << GetLastError() << std::endl;
        CloseHandle(hDevice);
        return 1;
    }
    switch (ioctlCode) {
    case IOCTL_TRIGGER_FLAG_SEARCH:
    {
        ioctlDescription = "Trigger Flag Search";
        FLAG_SEARCH_REQUEST flagSearchRequest;
        // Set up the flag search request parameters
        // ...
        inputBuffer = &flagSearchRequest;
        inputSize = sizeof(FLAG_SEARCH_REQUEST);
        outputBuffer = &flagSearchRequest;
        outputSize = sizeof(FLAG_SEARCH_REQUEST);
        break;
    }
    case IOCTL_READ_MEMORY_OFFSET:
    {
        ioctlDescription = "Read Memory Offset";
        READ_MEMORY_REQUEST readMemoryRequest;

        // Set up the read memory request parameters
        std::cout << "Enter the source address: ";
        std::cin >> readMemoryRequest.SourceAddress;
        std::cout << "Enter the destination buffer address: ";
        std::cin >> readMemoryRequest.DestinationBuffer;
        std::cout << "Enter the size of memory to read: ";
        std::cin >> readMemoryRequest.Size;

        inputBuffer = &readMemoryRequest;
        inputSize = sizeof(READ_MEMORY_REQUEST);
        outputBuffer = &readMemoryRequest;
        outputSize = sizeof(READ_MEMORY_REQUEST);
        break;
    }
    case IOCTL_DUMP_LOADED_MODULES:
    {
        ioctlDescription = "Dump Loaded Modules";
        DUMP_MODULES_REQUEST dumpModulesRequest;
        ULONG modulesBufferSize = sizeof(MODULE_INFO) * 1024;
        std::vector<MODULE_INFO> modulesBuffer(modulesBufferSize);
        dumpModulesRequest.ModulesBuffer = modulesBuffer.data();
        dumpModulesRequest.BufferLength = modulesBufferSize;

        inputBuffer = &dumpModulesRequest;
        inputSize = sizeof(DUMP_MODULES_REQUEST);
        outputBuffer = &dumpModulesRequest;
        outputSize = sizeof(DUMP_MODULES_REQUEST);

        if (!ExecuteIoctl(hDevice, ioctlCode, inputBuffer, inputSize, outputBuffer, outputSize, &bytesReturned)) {
            std::cerr << "Failed to execute IOCTL. Error: " << GetLastError() << std::endl;
            CloseHandle(hDevice);
            return 1;
        }

        // Validate the output buffer size
        if (bytesReturned < sizeof(DUMP_MODULES_REQUEST)) {
            std::cerr << "Invalid response received from IOCTL." << std::endl;
            CloseHandle(hDevice);
            return 1;
        }

        DUMP_MODULES_REQUEST* dumpModulesResponse = reinterpret_cast<DUMP_MODULES_REQUEST*>(outputBuffer);
        std::vector<MODULE_INFO> modules(dumpModulesResponse->ModulesBuffer, dumpModulesResponse->ModulesBuffer + dumpModulesResponse->ModulesCount);
        std::string folderPath = "Modules_" + processName;
        std::wstring wideFolderPath(folderPath.begin(), folderPath.end());
        CreateDirectory(wideFolderPath.c_str(), nullptr);

        SaveModuleInfo(modules, folderPath);

        std::cout << "IOCTL (" << ioctlDescription << ") executed successfully." << std::endl;
        std::cout << "Module information saved in the '" << folderPath << "' folder." << std::endl;
        break;
    }

    HANDLE hDevice = CreateFile(L"\\\\.\\MyMemoryReader", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hDevice == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to open device. Error: " << GetLastError() << std::endl;
        return 1;
    }

    DWORD bytesReturned;
    if (!ExecuteIoctl(hDevice, ioctlCode, inputBuffer, inputSize, outputBuffer, outputSize, &bytesReturned)) {
        std::cerr << "Failed to execute IOCTL. Error: " << GetLastError() << std::endl;
        CloseHandle(hDevice);
        return 1;
    }

    if (ioctlCode == IOCTL_DUMP_LOADED_MODULES) {
        DUMP_MODULES_REQUEST* dumpModulesResponse = reinterpret_cast<DUMP_MODULES_REQUEST*>(outputBuffer);
        std::vector<MODULE_INFO> modules(dumpModulesResponse->ModulesBuffer, dumpModulesResponse->ModulesBuffer + dumpModulesResponse->ModulesCount);
        std::string folderPath = "Modules_" + processName;
        std::wstring wideFolderPath(folderPath.begin(), folderPath.end());
        CreateDirectory(wideFolderPath.c_str(), nullptr);

        SaveModuleInfo(modules, folderPath);

        std::cout << "IOCTL (" << ioctlDescription << ") executed successfully." << std::endl;
        std::cout << "Module information saved in the '" << folderPath << "' folder." << std::endl;
    }
    else {
        std::cout << "IOCTL (" << ioctlDescription << ") executed successfully." << std::endl;
    }

    CloseHandle(hDevice);
    return 0;
    }

}
