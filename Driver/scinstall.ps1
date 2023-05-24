echo "1st thing you need to disable signed driver enforcement because we are not running a signed driver yet, we also need to be admin to install and start the driver so Push Enter!"
pause
# Get the ID and security principal of the current user account
$myWindowsID = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$myWindowsPrincipal = new-object System.Security.Principal.WindowsPrincipal($myWindowsID)

# Get the security principal for the administrator role
$adminRole = [System.Security.Principal.WindowsBuiltInRole]::Administrator

# Check to see if we are currently running as an administrator
if ($myWindowsPrincipal.IsInRole($adminRole))
{
   # We are running as an administrator, so change the title and background color to indicate this
   $Host.UI.RawUI.WindowTitle = $myInvocation.MyCommand.Definition + "(Elevated)"
   $Host.UI.RawUI.BackgroundColor = "DarkBlue"
   clear-host
}
else
{
   # We are not running as an administrator, so relaunch the script as administrator

   # Create a new process object that starts PowerShell
   $newProcess = new-object System.Diagnostics.ProcessStartInfo "PowerShell";

   # Specify the current script path and name as a parameter
   $newProcess.Arguments = $myInvocation.MyCommand.Definition;

   # Indicate that the process should be elevated
   $newProcess.Verb = "runas";

   # Start the new process
   [System.Diagnostics.Process]::Start($newProcess);

   # Exit from the current, unelevated, process
   exit
}

# Run your code that needs to be elevated here
try {
    echo "$PSScriptRoot"
    echo "Push Enter!"
    pause
    # Load the driver (Replace 'drivername' and 'driverpath' with your specific driver name and path)
    sc.exe create Project7 type= kernel binPath= "$PSScriptRoot\x64\Release\KMDFDriver5.sys"

    # Start the driver
    sc.exe start Project7

} catch {
    Write-Host $_.Exception.Message
    pause
}
pause
