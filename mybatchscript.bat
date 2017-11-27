echo @off
set local

set filepath="%userprofile%\Documents\WindowsDiagnosticReport_%computername%_%DATE:~10,4%_%DATE:~4,2%_%DATE:~7,2%%TIME:~0,2%_%TIME:~3,2%_%TIME:~6,2%.txt"

echo %filepath%
echo ---System OS and Processor--- >> %filepath%
systeminfo | findstr C:/"Host Name" >> %filepath%
systeminfo | findstr C:/"Processor" >> %filepath%
echo. >> %filepath%
echo. >> %filepath%
echo Environment Variables >> %filepath%
echo. >> %filepath%
echo filepath = %userprofile%\Documents\WindowsDiagnosticReport_%computername%_%DATE:~10,4%_%DATE:~4,2%_%DATE:~7,2%%TIME:~0,2%_%TIME:~3,2%_%TIME:~6,2%.txt
echo. >> %filepath%
echo ---Network Configuration--- >> %filepath%
ipconfig >> %filepath%

echo. >> %filepath%
echo. >> %filepath%

echo ---Running Processes--- >> %filepath%
echo. >> %filepath%
tasklist >> %filepath%

echo. >> %filepath%
echo ---Startup Programs--- >> %filepath%
wmic /APPEND:%filepath% STARTUP get caption,command /format:list>Nul
echo. >> %filepath%

echo ---Scheduled Tasks--- >> %filepath%
echo. >> %filepath%
schtasks /query >> %filepath%
echo. >> %filepath%

echo ---Autorun:Runonce--- >> %filepath%
REG query HKLM\Software\Microsoft\Windows\CurrentVersion\Runonce >> %filepath%
REG query HKLM\Software\Microsoft\Windows\CurrentVersion\policies\Explorer\Run >> %filepath%
REG query HKLM\Software\Microsoft\Windows\CurrentVersion\Run >> %filepath%
REG query HKCU\Software\Microsoft\Windows NT\CurrentVersion\Run >> %filepath%
REG query HKCU\Software\Microsoft\Windows\Currentversion\Run >> %filepath%
REG query HKCU\Software\Microsoft\Windows\CurrentVersion\Runonce >> %filepath%
echo. >> %filepath%

echo ---Most Recently Used Commands--- >> %filepath%
REG query HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU >> %filepath%
echo. >> %filepath%

echo ---UserAssit Key--- >> %filepath%
REG query HCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssit >> %filepath%
echo. >> %filepath%

echo ---Wireless Network Settings--- >> %filepath%
REG query HKLM\Software\microsoft\WZCSVC\Parameters\Interfaces >> %filepath%
REG query HKLM\SYSTEM\ControlSet001\Services\Tcpip\Parameters\Interfaces >> %filepath%
echo. >> %filepath%

echo ---LAN Devices--- >> %filepath%
REG query HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComputerDescriptions >> %filepath%
echo. >> %filepath%

echo ---USB Devices--- >> %filepath%
REG query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USB >> %filepath%
echo. >> %filepath%

echo ---Internet Explorer Settings--- >> %filepath%
REG query "HKCU\Software\Microsoft\Internet Explorer\Main" >> %filepath%
echo. >> %filepath%

echo ---URLS Visited--- >> %filepath%
REG query "HKCU\Software\Microsoft\Internet Explorer\TypedURLs" >> %filepath%
echo. >> %filepath%

echo ---Enabling UAC Control--- >> %filepath%
reg ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 1 /f

echo ---Disabling Run & CMD Command--- >> %filepath%
reg ADD HKCU\SOFTWARE\Microsoft\Policies\Microsoft\Windows\System /v DisableCMD /t REG_DWORD /d 2 /f

echo ---Deleting REG Keys--- >> %filepath%
reg delete HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\WindowsUpdate\AU\NoAUAsDefaultShutdownOption 
reg delete HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\EnableBalloonTips
reg delete HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoDrives

echo ---DONE--- >> %filepath%

call :treeProcess

set mydir="C:\Users\"
set "deny=.avi .mov .wav .flv .mp4 .wmv .mpg .mpeg .mp3 .wma .mid .ogg"

:treeProcess

for %%f in (%deny%) do echo %%f
for /D %%d in (%mydir%) do (
	cd %%d
	call :treeProcess
	cd .. 
)
exit /b 





	
	






