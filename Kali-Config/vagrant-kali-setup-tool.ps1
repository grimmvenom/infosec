#====================================================================
# Tony Karre @tonykarre
#
# Concept - Assume you have multiple projects/engagements where each project
# needs a separate Kali VM coupled with a separate shared folder.
# Furthermore, you want the shared folder to be a bitlocker-encrypted virtual disk
# whose name matches your project name.  Every project will have its own virtual disk.
#
# This tool does the setup for a new project - creates your encrypted disk and uses vagrant to launch a project-specific Kali VM.
#
# Basic solution steps -
#    1.  Designate a project name for your project - assume "my-project" for this example.
#    2.  Within some specified parent folder, create a child folder named "my-project".  This is your "project folder".
#    3.  Create a virtual drive with the name "my-project.vhdx", bitlocker encrypt it, and map it to a drive letter (e.g., "G:")
#    4.  Setup some environment variables that will hold project folder-related paths.
#        We'll use environment variables as a way to inject path information into the "vagrant init" process.
#    5.  cd into the new project folder and execute a 'vagrant init --template "%KALI_SETUP_TEMPLATE_PATH%" kalilinux/rolling'
#        This creates a project-specific Vagrantfile.
#    6.  Execute an initial "vagrant up" to create the Vagrant VM (we'll assume virtualbox as our VM provider for Vagrant).
#        This initial VM will not have encrypted storage yet.
#    7.  Immediately execute a "vagrant halt" to shutdown the box
#    8.  Apply encryption to the VM storage
#    9.  Do a second "vagrant up" to fire up the box. Now everything is encrypted.
#
# After working, just shutdown from within Kali, or do a "vagrant halt" to shutdown the VM.
# You can "Eject" the mapped drive too.  Then it will just sit as an vhdx file on your laptop.
# Later you can remount the encrypted drive, then do a "vagrant up" to start up your project-specific Kali.
#
# Notes:
#
# 1. This script performs a few operations that need to run elevated.  If you don't run this from an administrator command prompt, the script exits.
#
#    * Patching Vagrant requires admin privs
#    * Using diskpart.exe to create the virtual drive requires admin privs
#    * Running bitlocker to encrypt the virtual drive requires admin privs
#
# 2. Vagrant (at least as of 2.2.5) needs patching to support the survival of the "vagrant up" operation at the point the boot process
#    pauses to allow you to type in the virtualbox encryption password.  This script attempts to see if the patch needs applied, then patches it if needed.
#    Read down below for a deeper discussion.  If you don't patch, then "vagrant up" aborts during the boot process, and certain things like folder sharing fail.
#
# 3. Environment variables set by this script (process only):
#    KALI_SETUP_TEMPLATE_PATH = full path to the Vagrantfile.erb file, e.g., c:\mypath\Vagrantfile.erb
#    KALI_SETUP_HOST_SYNCED_FOLDER_PATH = host path to the shared folder. e.g., "G:/" for a mounted virtual drive
#    KALI_SETUP_VM_SYNCED_FOLDER_PATH = kali path to the shared folder.  e.g., "/my-project"
#
#====================================================================


# We will be doing several operations that need to run elevated:
#
#  1. we might need to patch vagrant.
#  2. we need to run diskpart.exe to create a virtual disk, and that requires admin privileges
#  3. we need to run bitlocker to encrypt our virtual disk, and that also requires admin privileges
#
# Exit if we aren't running as administrator

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Host "[-] Please run this script from an elevated command prompt - we need to run as administrator." -ForegroundColor Red
  exit
}

# Choose a different vagrant box if you want something different

$vagrantbox = "kalilinux/rolling"

# Change this if you want a bigger virtual disk:

$virtualdisksize = "64"  # 64 MB. This is the minimum size for bitlocker to work.  You can make this bigger if you need to.

# Setup a required function we'll need.  We'll be trying to use a directory browser to allow you to pick a directory
# and you need to do some extra work to force that thing to show up in the foreground
# This function will do that.

# courtesy of: https://stackoverflow.com/questions/54037292/folderbrowserdialog-bring-to-front

# Show an Open Folder Dialog and return the directory selected by the user.
# This function is needed because it handles showing the directory browser on top of all other windows.

Function Get-FolderName {
    # To ensure the dialog window shows in the foreground, you need to get a Window Handle from the owner process.
    # This handle must implement System.Windows.Forms.IWin32Window
    # Create a wrapper class that implements IWin32Window.
    # The IWin32Window interface contains only a single property that must be implemented to expose the underlying handle.
    $code = @"
using System;
using System.Windows.Forms;

public class Win32Window : IWin32Window
{
    public Win32Window(IntPtr handle)
    {
        Handle = handle;
    }

    public IntPtr Handle { get; private set; }
}
"@

    if (-not ([System.Management.Automation.PSTypeName]'Win32Window').Type) {
        Add-Type -TypeDefinition $code -ReferencedAssemblies System.Windows.Forms.dll -Language CSharp
    }

    # Get the window handle from the current process
    # $owner = New-Object Win32Window -ArgumentList ([System.Diagnostics.Process]::GetCurrentProcess().MainWindowHandle)
    # Or write like this:

    $owner = [Win32Window]::new([System.Diagnostics.Process]::GetCurrentProcess().MainWindowHandle)

    # Or use the the window handle from the desktop
    # $owner =  New-Object Win32Window -ArgumentList (Get-Process -Name explorer).MainWindowHandle
    # Or write like this:
    # $owner = [Win32Window]::new((Get-Process -Name explorer).MainWindowHandle)

    $FolderBrowser = New-Object System.Windows.Forms.FolderBrowserDialog -Property @{
        SelectedPath = [System.Environment+SpecialFolder]::MyComputer
        ShowNewFolderButton = $true
        Description = "Choose a parent folder for the new Kali project"
    }

    # set the return value only if a selection was made

    $result = $null
    If ($FolderBrowser.ShowDialog($owner) -eq "OK") {
        $result = $FolderBrowser.SelectedPath
    }

    # clear the dialog from memory

    $FolderBrowser.Dispose()

    return $result
}

# Now confirm that we have our prequisites in place.  Start by confirming that we have Vagrant installed.

try {

  Write-Host "[+] Checking to see if Vagrant is installed.  It should be in your `$PATH"

  $appInfoObj = Get-Command -Name "vagrant.exe" -CommandType Application -ErrorAction:Stop  # if not found, an exception is thrown
  $vagrantexe = $appInfoObj.Source

}
catch {
  Write-Host "[-] Vagrant does not appear to be installed.  Exiting." -ForegroundColor Red
  exit
}

Write-Host "[+] Found vagrant" -ForegroundColor Green

Write-Host "[+] Checking to see if Virtualbox is installed (specifically VBoxManage.exe).  It may not always be in your `$PATH"

# assume 64-bit VirtualBox, hence "program files", not "program files(x86)"

$vbmgexe = Get-ChildItem -Path $env:ProgramFiles -File -Name "VBoxManage.exe" -Recurse

if ($vbmgexe) {

  Write-Host "[+] Found Virtualbox" -ForegroundColor Green
  $vbmgexe = "$($env:ProgramFiles)\$($vbmgexe)"

} else {
  Write-Host "[-] Virtualbox does not appear to be installed.  Exiting." -ForegroundColor Red
  exit
}

# Confirming that we have the Bitlocker device encryption tool installed.

try {

  Write-Host "[+] Checking to see if Bitlocker is installed.  It should be in your `$PATH"

  $appInfoObj = Get-Command -Name "manage-bde.exe" -CommandType Application -ErrorAction:Stop  # if not found, an exception is thrown
  $bitlockerexe = $appInfoObj.Source

}
catch {
  Write-Host "[-] Bitlocker does not appear to be installed.  Exiting." -ForegroundColor Red
  exit
}

Write-Host "[+] Found Bitlocker" -ForegroundColor Green

Write-Host "[+] Checking to see if we need to patch vagrant"


# Now let's see if we have to patch Vagrant.
#
# Here's the issue - We will be creating a VM that has an encrypted storage device.
# When VirtualBox boots up the VM, it will "pause" to allow you to type in the encryption password.
# Unfortunately, vagrant doesn't realize this is going to happen.  When vagrant boots the VM, it
# monitors the state of the box to make sure that all is well.  The allowable machine states are "starting" and "running".
# When vagrant sees "paused", it considers that to be an error state and aborts the rest of the startup process.
# The box will still boot, but post-boot steps like setting up the synced folder won't happen.

# So the workaround is to patch vagrant by adding "paused" to the allowable machine states in the "self.action_boot" section of the file action.rb, found in a path like this:
#    C:\HashiCorp\Vagrant\embedded\gems\2.2.5\gems\vagrant-2.2.5\plugins\providers\virtualbox\action.rb

# Get the root path of our vagrant executable

$vagrantbin = Split-Path -Path "$vagrantexe"

# Now try to resolve the path of our action.rb file.  We'll wildcard the directories that have version numbers in them.

try {
 $actionrb = $(Resolve-Path -Path "$($vagrantbin)\..\embedded\gems\*\gems\*\plugins\providers\virtualbox\action.rb" -ErrorAction:Stop)[0].Path
}
catch {
  Write-Host "[-] Couldn't find the action.rb file we were looking for - this was unexpected.  Exiting." -ForegroundColor Red
  exit
}

# OK - we found the action.rb file.  Let's see if we need to patch it.
#
# Here is the original section of the file we are interested in:
#
#   # This action boots the VM, assuming the VM is in a state that requires
#   # a bootup (i.e. not saved).
#   def self.action_boot
#     Vagrant::Action::Builder.new.tap do |b|
#       b.use CheckAccessible
#       b.use CleanMachineFolder
#       b.use SetName
#       b.use ClearForwardedPorts
#       b.use Provision
#       b.use EnvSet, port_collision_repair: true
#       b.use PrepareForwardedPortCollisionParams
#       b.use HandleForwardedPortCollisions
#       b.use PrepareNFSValidIds
#       b.use SyncedFolderCleanup
#       b.use SyncedFolders
#       b.use PrepareNFSSettings
#       b.use SetDefaultNICType
#       b.use ClearNetworkInterfaces
#       b.use Network
#       b.use NetworkFixIPv6
#       b.use ForwardPorts
#       b.use SetHostname
#       b.use SaneDefaults
#       b.use Customize, "pre-boot"
#       b.use Boot
#       b.use Customize, "post-boot"
#       b.use WaitForCommunicator, [:starting, :running]
#       b.use Customize, "post-comm"
#       b.use CheckGuestAdditions
#     end
#   end
#
# We want to change this:
#
#       b.use WaitForCommunicator, [:starting, :running]
#
# to this:
#
#       b.use WaitForCommunicator, [:starting, :paused, :running]
#

# The string "[:starting, :running]" only occurs once in the original file, so we can do a string replace with "[:starting, :paused, :running]"

# Have we already patched?

if (Select-String -Pattern "[:starting, :paused, :running]" -Path $actionrb -SimpleMatch -Quiet) {
  Write-Host "[+] Vagrant has already been patched." -ForegroundColor Green
} else {

  # It looks like we haven't patched yet.

  Write-Host "[+] We need to patch Vagrant"

  # Let's make a copy of the original file so you can restore it if you want.

  try {

    $actionrbcopy = "$($actionrb).original"

    Copy-Item -Path $actionrb -Destination $actionrbcopy -ErrorAction:Stop

    Write-Host "[+] Copied the original file to $actionrbcopy"

  }
  catch {
    Write-Host "[-] Failed to create the file $actionrbcopy" -ForegroundColor Red
    Write-Host "[-] Make sure you are elevated as admin when running this script. Exiting." -ForegroundColor Red
    exit
  }

  # Now attempt to patch the file

  try {

    # Read the content from the unpatched file

    $content = Get-Content -Path $actionrb -ErrorAction:Stop

    # Patch our line of code

    $newContent = $content -replace "\[:starting, :running\]", "[:starting, :paused, :running]"

    # Now update the file with our new content

    $newContent | Set-Content -Path $actionrb -ErrorAction:Stop

    Write-Host "[+] Successfully patched vagrant" -ForegroundColor Green

  }
  catch {
    Write-Host "[-] Failed to patch the file $actionrb" -ForegroundColor Red
    Write-Host "[-] Exiting." -ForegroundColor Red
    exit
  }


}  # end if (Select-String -Pattern "[:starting, :paused, :running]" else clause




# Ok, here we go with the real work.  Start by locating the Vagrantfile.erb file.

# Let's start by assuming that the Vagrantfile.erb file is co-located with this powershell script.
# That would be the case if someone cloned our github repo, etc.

$erbtemplatefile = "$($PSScriptRoot)/Vagrantfile.erb"

# Let's see if our Vagrantfile.erb is actually there.

if (Test-Path -LiteralPath $erbtemplatefile) {
  Write-Host "[+] Found $erbtemplatefile. Will use it as our ERB template file.  Continuing." -ForegroundColor green
} else {

  # The Vagrantfile.erb file was not colocated with this script.  Let's ask the user where it is...
  # Get the desired filename using a system dialog box.

  Write-Host "[+] Getting the path to the Vagrantfile.erb template file"

  [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") | Out-Null

  $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog

  $OpenFileDialog.Title = "Find the Vagrantfile.erb template file"
  $OpenFileDialog.initialDirectory = [Environment]::GetEnvironmentVariable("userprofile")
  $OpenFileDialog.filter = "Vagrant ERB Files (*.erb)| *.erb"

  $OpenFileDialog.ShowDialog() | Out-Null

  # If the cancel button is clicked, then we'll get a zero-length filename

  if ($OpenFileDialog.filename.length -eq 0) {

    Write-Host "[-] Canceled." -ForegroundColor red
    exit
  }

  # at this point we should have a valid filename.

  $erbtemplatefile = $OpenFileDialog.filename

  Write-Host "[+] ERB template file: $erbtemplatefile" -ForegroundColor Green

}


# Get the parent path where we want to create our new project directory.

Write-Host "[+] Getting the folder in which we want to create the new Kali project folder"

$parentfolder = Get-FolderName

# If the cancel button is clicked, then we'll get a zero-length filename

if ($parentfolder.length -eq 0) {

  Write-Host "[-] Canceled." -ForegroundColor red
  exit
}

# at this point we should have a valid foldername.

Write-Host "[+] Selected project parent folder: $parentfolder" -ForegroundColor Green

# Now let's get the name of our new project.  If all goes well, we'll create a new folder by that name.

Write-Host "`nType the name or ID of your Kali project (max 32 chars, none of these chars: *?.,;:/\|+=<>[]). Examples: 12345 or my-proj" -ForegroundColor Cyan
$projname = Read-Host "Enter your desired project name (or Q to quit)"

if ($projname.length -eq 0 -or $projname -eq "Q" -or $projname -eq "q") {
  Write-Host "[-] Canceled." -ForegroundColor red
  exit
}

# Enforce the max 32 char string length. We will use the projectname as our virtual disk NTFS label, hence the restriction.

if ($projname.length -gt 32) {

  $projname = $projname.substring(0, 32)
  Write-Host "[+] Truncating the project name to 32 characters: $projname" -ForegroundColor Green

} else {
  Write-Host "[+] Entered project name: $projname" -ForegroundColor Green
}



# Now let's see if we already have a folder with the entered project name. If so, we'll bail.

$projfolder = "$($parentfolder)\$($projname)"

Write-Host "[+] Checking to see if folder $projfolder already exists"

if (Test-Path -LiteralPath $projfolder) {
  Write-Host "[-] Folder $projfolder already exists!  Exiting." -ForegroundColor red
  exit
}

Write-Host "[+] folder $projfolder does not exist yet." -ForegroundColor Green

# Now let's get the desired drive letter that we will (eventually) mount a new virtual drive on.
# If the drive letter is already in use, then we'll bail out again.

Write-Host "`n[+] Here is a list of your currently mounted drives:" -ForegroundColor Cyan

Get-WMIObject Win32_LogicalDisk | ForEach-Object -Process {"$($_.DeviceID) - $($_.Volumename)"}

Write-Host "`nEnter a Drive Letter (e.g., G, P, X, etc.) on which you want your new virtual drive to be mounted." -ForegroundColor Cyan
$driveletter = Read-Host "Drive letter (or Q to quit)"

# do some validation of our drive letter

if ($driveletter.Length -eq 0 -or $driveletter -eq "Q" -or $driveletter -eq "q") {
  Write-Host "[-] Canceled." -ForegroundColor red
  exit
}

if (-not ($driveletter.Length -eq 1) -or -not ($driveletter -match "[a-z,A-Z]")) {
  Write-Host "[-] Error - a drive letter must be a single character in the range [a-z,A-Z]" -ForegroundColor red
  exit
}

Get-WMIObject Win32_LogicalDisk | ForEach-Object -Process {
  if ($_.DeviceID -eq "$($driveletter):") {
    Write-Host "[-] Error - drive $driveletter is already in use!" -ForegroundColor red
    exit
  }
}

Write-Host "[+] Your selected drive will be $($driveletter):" -ForegroundColor Green

# build the full filename for the virtual disk file

$Virtualdiskfile = "$projfolder\$($projname).vhdx"

# Now provide a summary of all of this to the user.  If you are happy with it, then we'll continue.

Write-Host "`nHere is the configuration you selected:" -ForegroundColor Cyan
Write-Host "Vagrant template ERB file: $erbtemplatefile" -ForegroundColor Green
Write-Host "Project parent folder: $parentfolder" -ForegroundColor Green
Write-Host "Project name: $projname" -ForegroundColor Green
Write-Host "Project folder to be created: $projfolder" -ForegroundColor Green
Write-Host "Virtual Disk File to be created: $Virtualdiskfile" -ForegroundColor Green
Write-Host "Drive letter for your encrypted virtual disk will be $($driveletter):" -ForegroundColor Green

$readytocontinue = Read-Host "`nDo you want to continue? (Y/N)"

if ($readytocontinue -ne "Y" -and $readytocontinue -ne "y") {
  Write-Host "[-] Canceled." -ForegroundColor red
  exit
}

Write-Host "[+] Configuration has been approved. Starting setup."

# Create the desired project folder

Write-Host "[+] Creating project folder: $projfolder"

try {
  $projfolderObj = New-Item -ItemType "directory" -Path $projfolder
} catch {
  Write-Host "[-] Error - failed to create directory $projfolder" -ForegroundColor red
  exit
}

Write-Host "[+] Project folder created." -ForegroundColor Green

# Now build the script that diskpart will use to create the virtual disk file.
# The script will live in a temporary file.

try {

  Write-Host "[+] Creating diskpart script file"

  # create the temporary file

  $tempfile = New-TemporaryFile

  # Now build the script file

  Add-Content -Path $tempfile.FullName -Value "create vdisk file=`"$Virtualdiskfile`" maximum=$virtualdisksize"
  Add-Content -Path $tempfile.FullName -Value "select vdisk file=`"$Virtualdiskfile`""
  Add-Content -Path $tempfile.FullName -Value "attach vdisk"
  Add-Content -Path $tempfile.FullName -Value "create partition primary"
  Add-Content -Path $tempfile.FullName -Value "format fs=NTFS label=`"$projname`""
  Add-Content -Path $tempfile.FullName -Value "assign letter=$driveletter"
  Add-Content -Path $tempfile.FullName -Value "exit"

  Write-Host "[+] diskpart script file created." -ForegroundColor Green

} catch {
  Write-Host "[-] Error - failed to create the diskpart script file" -ForegroundColor red
  exit
}

# Now that we have a script file, let's run diskpart to create and mount the virtual disk.

try {

  & "diskpart.exe" "/s" "$($tempfile.FullName)"

  # delete the script file to clean up

  Remove-Item -LiteralPath $tempfile.FullName

  # check to see if this actually worked - we should have a virtual disk file and it should be mounted

  if (Test-Path -LiteralPath $Virtualdiskfile) {
    Write-Host "[+] Virtual disk created." -ForegroundColor Green
  } else {
    Write-Host "[-] Failed to create the virtual disk file $($virtualdiskfile)!  Exiting." -ForegroundColor red
    exit
  }

  if (Get-WMIObject -Query "select * from win32_LogicalDisk where DeviceID = '$($driveletter):'") {
    Write-Host "[+] Virtual disk mounted on $($driveletter):" -ForegroundColor Green
  } else {
    Write-Host "[-] Failed to mount the virtual disk on $($driveletter):!  Exiting." -ForegroundColor red
    exit
  }


} catch {
  Write-Host "[-] Error - failed to create and mount the virtual disk file" -ForegroundColor red
  exit
}


# Bitlocker-protect our new virtual disk.

try {

  & $bitlockerexe "-on" "$($driveletter):" "-rp" "-pw" "-used"

  Write-Host "[+] The virtual disk has been bitlocker-protected." -ForegroundColor Green

} catch {
  Write-Host "[-] Error - something failed in the bitlocker protection step." -ForegroundColor red
  exit
}


# Now let's perform the sequence of actions that will initialize our VM and setup storage encryption

try {

  Write-Host "[+] Setting up environment variables that will inject data into our Vagrantfile"

  # Setup environmnent variables that we'll used to inject data into our vagrant "Vagrantfile" file

  [System.Environment]::SetEnvironmentVariable("KALI_SETUP_TEMPLATE_PATH",$erbtemplatefile, "process")
  [System.Environment]::SetEnvironmentVariable("KALI_SETUP_HOST_SYNCED_FOLDER_PATH","$($driveletter):/", "process")
  [System.Environment]::SetEnvironmentVariable("KALI_SETUP_VM_SYNCED_FOLDER_PATH","/$($projname)", "process")

  # Run the Vagrant init process to build our unique Vagrantfile from the template

  Write-Host "[+] Running `"vagrant init`""

  & $vagrantexe "init" "--template" "`"$erbtemplatefile`"" "--output" "`"$($projfolder)\Vagrantfile`"" "$vagrantbox"

  # Drop into the new project folder and run a first-time vagrant up.  This will build the initial VM.
  # Vagrant will also create some metadata files, one of which we will harvest the Virtualbox box ID from.

  Write-Host "[+] Running a first-time startup of our box by running `"vagrant up`""

  cd $projfolder
  & $vagrantexe "up"

  # Now bring the box back down so we can encrypt its storage device

  Write-Host "[+] Running a `"vagrant halt`" to bring the box back down so we can encrypt its storage device"

  & $vagrantexe "halt"

  # To interact with this VM, we need to know its UUID.  It lives in the file ".vagrant\machines\default\virtualbox\id" in our project folder

  Write-Host "[+] Extracting the Virtualbox VM UUID"

  $boxUUID = $(Get-Content "$($projfolder)\.vagrant\machines\default\virtualbox\id")

  Write-Host "[+] Found VM UUID $boxUUID" -ForegroundColor Green

  # Get the name of the VM.  We'll use it later as a encryption password ID (not the password itself - just the ID).

  Write-Host "[+] Fetching the Virtualbox name for this VM"

  $vmboxinfo = $(& $vbmgexe "showvminfo" $boxUUID "--machinereadable")
  $vmname = $($vmboxinfo | Select-String -Pattern "^name=")
  $vmname = (($vmname -split "=")[1] -split '"')[1]

  Write-Host "[+] Virtualbox name = $vmname" -ForegroundColor Green

  # Fetch the Storage device image UUID.

  Write-Host "[+] Fetching the storage device image UUID"

  $storageUUID = $($vmboxinfo | Select-String -Pattern "ImageUUID")
  $storageUUID = (($storageUUID -split "=")[1] -split '"')[1]

  Write-Host "[+] Found Storage Image UUID $storageUUID" -ForegroundColor Green

  # Let's fetch the status of the encryption for the device.  If it is already encrypted, then we can just exit.

  Write-Host "[+] Determining the encryption status of the image"

  $encstatus = $(& $vbmgexe "showmediuminfo" $storageUUID | Select-String -Pattern "Encryption:")
  $encstatus = ($encstatus -split '\s+')[1]

  if ($encstatus -eq "enabled") {
    Write-Host "[-] Encryption is already enabled on this device. Exiting." -ForegroundColor Red
    exit
  }

  Write-Host "[+] Encryption is disabled (good - we have not encrypted it yet)."

  # Build the encryptionsemaphore file. This file will trigger vagrant to print a password reminder during "vagrant up"

  Write-Host "[+] Creating the .encryptionsemaphore file"

  $esfileObj = New-Item -ItemType "file" -Path "$($driveletter):/.encryptionsemaphore"

  # Now encrypt the device.  Note that the Vbmgexe program will ask for the actual encryption password.

  Write-Host "[+] Ready to encrypt the VM storage. We need a second password for that.  You'll also need it when booting the VM from here on." -ForegroundColor Green
  Write-Host "[+] Provide that additional password:" -ForegroundColor Green

  & $vbmgexe "encryptmedium" "$storageUUID" "--newpassword" "-" "--newpasswordid" "$vmname" "--cipher" "AES-XTS256-PLAIN64"

  Write-Host "[+] Running a `"vagrant up`" again to bring up our box"
  Write-Host "[+] Get ready to use that password for the first time:" -ForegroundColor Green

  & $vagrantexe "up"

} catch {
  Write-Host "[-] Error - something failed in the sequence of vagrant steps" -ForegroundColor red
}

# All done.  Finish by providing some instructions.

Write-Host "[+] FINISHED" -ForegroundColor green

Write-Host "`nYour VM should be up and running."
Write-Host "When you are finishing working in the VM, just shut it down normally and eject the mapped drive."
Write-Host "You can also perform a `"vagrant halt`" to shutdown the VM."
Write-Host "`nWhen you want to resume work, just remount the mapped drive then perform a `"vagrant up`" to boot the VM."
Write-Host "Remember that remounting the bitlocker-protected mapped drive will initially throw an error prior to asking for the password. Don't get faked out. The password entry form will be small and probably hiding on your primary monitor."
Write-Host "`nDon't forget to `"vagrant destroy`" the box when you are completely done with it, then keep the bitlocker-protected virtual disk file for later reference."

exit




