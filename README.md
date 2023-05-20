# KernelLook
simple kernel driver and user mode app to do some magic


This kernel-mode driver is built for the Microsoft Windows operating system and uses the Windows Driver Model (WDM). It primarily serves two functions:

Listing Process IDs (IOCTL_GET_PROCESS_IDS): This function retrieves the process identifier (PID) and the name of all running processes on the system. It uses the ZwQuerySystemInformation function to get the process information, which is returned to the user-mode application as an array of PROCESS_INFO structures.

Listing Loaded Modules for a Specific Process (IOCTL_GET_MODULES): This function retrieves all loaded modules (e.g., DLLs) for a specified process, using the PID. It first locates the process using the PsLookupProcessByProcessId function. Then, it traverses the loaded module list linked to the process's PEB (Process Environment Block), returning the base address, size, and name of each module in an array of MODULE_INFO structures.

The driver uses IOCTL (I/O Control) codes to receive commands from a user-mode application via a DeviceIoControl function. This design allows for the easy expansion of the driver's functionalities.

The device created by this driver is named "ModuleList", and it communicates with the user-mode application through the DispatchIoctl function, which handles the IOCTL codes. Additionally, it implements standard create and close dispatch functions for opening and closing a handle to the driver.

Finally, the driver can be unloaded safely, cleaning up the device and symbolic link that it created during its initialization.

From a user-mode application's perspective, this driver provides valuable insights about the running processes and their loaded modules, which can be used for a variety of purposes such as system monitoring, debugging, malware analysis, etc. The application can use the DeviceIoControl function to communicate with the driver, passing the appropriate IOCTL code and receiving the required information. The information returned by the driver can then be used for further analysis or action based on the application's purpose.
