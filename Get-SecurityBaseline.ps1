<#

.SYNOPSIS
Security for the paranoid! This script takes a snapshot of the current security posture for a local machine.

.DESCRIPTION
This script collects all the services, network connections, drivers, processes, hardware devices, startup programs, installed programs, group policies, certificates, environment variables and firewall rules for later comparison.
It is advised to run this script after every major upgrade or changes to the machine due to any hardware/software installation.

The output will be dumped in a folder with computer name 

.PARAMETER output

String: Specifies the output location where a folder will be created with logfiles.

.PARAMETER SysFileHashes

String: Enabling this parameter generates a hash of all the files under Windows's System32. Requires patience (might take longer!)

.EXAMPLE
Get-SecurityBaseline.ps1 -output "C:\Temp"
Creates an output folder in the Temp directory under C Drive.

Get-SecurityBaseline.ps1 -SysFileHashes -Verbose
Generates System32 file hashes along with standard output. Prints Verbose messages.

.NOTES
Close all the programs before running the script for capturing only the essential data.

Supports Windows 8 / Server 2012, Powershell 3 and above.

Future updates to this script would include automatic file comparisons between the previous and current snapshot for each category.

MIT License

Copyright (c) 2018 Abhijeet Jain

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

.LINK
https://theslickgeek.com/winsbl

#>


[CmdletBinding()]

Param(
[parameter(Position=0,Mandatory=$false)]
    [String[]]
    $output='.',

[switch]$SysFileHashes
 
)

#region prereqCheck

#Check if the instance is running as administrator and at least PS Version 3

If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
{
    Write-host "You do not have Administrator rights to run this script.`nPlease re-run this script as an Administrator!" -ForegroundColor Red -BackgroundColor Black
    Break
}

If ($(get-host).Version.Major -lt 3) 
{

    Write-Host "This Script is only supported on Powershell Version 3 and above!" -ForegroundColor Red -BackgroundColor Black
    Break

}

#endregion

#region outputFolder

$exist = 0 #For SysFileHash check

$curFolder = $(Get-location).Path

$dt = Get-Date -UFormat "%Y_%m_%d_%H_%M_%S"
$folderName = $env:COMPUTERNAME + "_" + $dt

If ($output -eq '.')
{
    Write-Verbose "Using current Folder for output files"
        
 }
 else
 {

    Write-Verbose -Message "Using this Folder for output files $output"
    Write-Verbose -Message "Creating Folder $folderName"
 }

  
 $outFolder = "$output\$folderName"

md $outFolder | Out-Null

cd $outFolder

#endregion

#region ComputerInfo

Write-Verbose -Message "Writing Computer Info..."

systeminfo.exe /fo list > ComputerInfo.txt

#endregion

#region UserInfo

$userCount = (gwmi win32_userAccount | where {$_.Disabled -match "False"} | measure).Count

"No of active users: $userCount" > UserInfo.txt
"----------------------------------------------------------------------" >> UserInfo.txt

query user >> UserInfo.txt

If ((gwmi win32_ComputerSystem).partofdomain -eq $false)

{
    
    Write-Host "This computer is not part of a domain" -foregroundcolor DarkBlue -BackgroundColor Yellow

    Write-Verbose "Writing local user info..."

    #loop around get-localgroup and get-localgroupmember

    #(get-localgroup).Name 

    #get-localgroupmember <group name>

    foreach ($group in ((Get-LocalGroup).Name)) {}

    foreach ($user in ((get-localuser).Name))
    {
    
        if ($user -eq $env:username) 

        {
        
            whoami /all >> UserInfo.txt

            "------------------------------------------------------------------------------------------------------" >> UserInfo.txt
        
        }
        
        net user $user >> UserInfo.txt

        "------------------------------------------------------------------------------------------------------" >> UserInfo.txt
    
    }
        
}
 
else

{ 

    Write-Host -Message "This computer is part of a domain but this script only collects local user information" -foregroundcolor DarkBlue -BackgroundColor Yellow

    Write-Verbose "Writing local user info..."

     foreach ($user in ((get-localuser).Name))
    {
    
        if ($user -eq $env:username) 

        {
        
            whoami /all >> UserInfo.txt

           "------------------------------------------------------------------------------------------------------" >> UserInfo.txt
        
        }
        
        net user $user >> UserInfo.txt

        "------------------------------------------------------------------------------------------------------" >> UserInfo.txt
    
    }

}

#endregion

#region ServiceInfo


Write-Verbose "Writing Services Info..."

gsv | sort StartType | sort Status -Descending | Select-Object -Property ServiceName,DisplayName,StartType,Status > ServicesInfo.txt

#endregion

#region SchTasksInfo

Write-Verbose "Writing list of all Scheduled Tasks - requires autorunsc which is included in the tools folder"

cd $curFolder

.\Tools\autorunsc.exe -nobanner -a t -h -s * > $outFolder\SchTasksInfo.txt

#endregion

#region CertInfo

Write-Verbose "Writing Machine and User Certificate Policy Info - requires sigcheck tool from SysInternals which is included in the tools folder"

.\Tools\sigcheck.exe -accepteula -nobanner -t * > $outFolder\MachineCertInfo.txt

.\Tools\sigcheck.exe -accepteula -nobanner -tu * > $outFolder\UserCertInfo.txt

#endregion

#region AutoRunInfo

Write-Verbose "Writing list of all Services, Programs and Scheduled Tasks which start automatically - requires autorunsc from SysInternals which is included in the tools folder"

.\Tools\autorunsc.exe -accepteula -nobanner -a s -h -s * > $outFolder\AutoRunInfo_Ser.txt

.\Tools\autorunsc.exe -accepteula -nobanner -a t -h -s * > $outFolder\AutoRunInfo_SchTasks.txt

.\Tools\autorunsc.exe -accepteula -nobanner -h -s * > $outFolder\AutoRunInfo_Prog.txt

cd $outFolder


#endregion

#region ProcessInfo

Get-Process -IncludeUserName | Select-Object ProcessName,Id, `
@{Label = "NPM(K)"; Expression = {[int]($_.NPM / 1024)}}, `
@{Label = "PM(K)"; Expression = {[int]($_.PM / 1024)}}, `
@{Label = "WS(K)"; Expression = {[int]($_.WS / 1024)}}, `
@{Label = "CPU(s)"; Expression = {if ($_.CPU) {$_.CPU.ToString("N")}}}, `
UserName,path | ft > ProcessInfo.txt

"--------------------------------------------------" >> ProcessInfo.txt

"Command Line:" >> ProcessInfo.txt

gwmi win32_process | Select-Object commandline >> ProcessInfo.txt


#endregion

#region DriverInfo

Write-Verbose "Writing Driver Info..."

gwmi win32_systemdriver | sort State | ft DisplayName,Name,State,Status -AutoSize > DriverInfo.txt

#endregion

#region GPOInfo

Write-Verbose "Writing Local Group Policy Info..."

gpresult.exe /scope computer /v > GPOInfo.txt

#endregion

#region FirewallInfo

"For protocol numbers, refer to: https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml" > FirewallInfo.txt

"`nCommon Ports: `n6=TCP `n17=UDP `n58=IPv6-ICMP `n41=IPv6" >> FirewallInfo.txt

"`nDirection: `n1=Inbound; `n2=Outbound" >> FirewallInfo.txt

"`nProfiles: `n1=Domain `n2=Private `n3=Domain,Private `n4=Public `n5=Domain,Public `n6=Private,Public `n7=Domain,Public,Private" >> FirewallInfo.txt

"`nList of Active Firewall Rules: `n`n" >> FirewallInfo.txt

Write-Verbose "Writing Active Firewall Rules Info..."

$fw=New-object -comObject HNetCfg.FwPolicy2

$fw.rules | where {$_.Enabled -match "True"} | sort ApplicationName | ft -Property ApplicationName,protocol,localports,localaddresses,remoteports,remoteaddresses,direction,profiles,description -GroupBy ApplicationName >> FirewallInfo.txt

#endregion

#region hardwareInfo

Write-Verbose "Writing Hardware Info..."

gwmi win32_computersystem | select-object -Property AdminPasswordStatus,BootupState,PowerOnPasswordStatus > HardwareInfo.txt

gwmi win32_bios | select-object -Property SerialNumber,Version,BIOSVersion,CurrentLanguage >> HardwareInfo.txt

gwmi win32_processor | select-object -Property CpuStatus,MaxClockSpeed,ProcessorType,CurrentClockSpeed,NumberofCores,NumberofEnabledCores,NumberofLogicalProcessors,ProcessorID,VirtualizationFirmwareEnabled >> HardwareInfo.txt

gwmi win32_logicaldisk | Select-Object -Property DeviceID,Name,Description,MediaType,FileSystem, {$_.FreeSpace /1GB}, {$_.Size / 1GB} ,VolumeSerialNumber,VolumeName  >> HardwareInfo.txt

If ($(gwmi win32_operatingsystem).Caption -like '*Server*') {

If ($(get-windowsfeature Bitlocker).InstallState -eq 'Available') { 

"The Machine does not have Bitlocker Feature Installed" >> HardwareInfo.txt

}

Else {

Get-BitLockerVolume | Select-Object -Property VolumeType,MountPoint,CapacityGB,VolumeStatus,EncryptionPercentage,KeyProtector,AutoUnlockEnabled,ProtectionStatus,LockStatus >> HardwareInfo.txt

}

}

Else {

Get-BitLockerVolume | Select-Object -Property VolumeType,MountPoint,CapacityGB,VolumeStatus,EncryptionPercentage,KeyProtector,AutoUnlockEnabled,ProtectionStatus,LockStatus >> HardwareInfo.txt

}

gwmi win32_physicalmemoryarray | Select-Object -Property MaxCapacity,MemoryDevices,Use  >> HardwareInfo.txt

"List of Active USB drives:" >> HardwareInfo.txt

"----------------------------------------------------------------------" >> HardwareInfo.txt

gwmi win32_diskdrive | Where { $_.InterfaceType –eq ‘USB’ }


#endregion

#region AppInfo

Get-AppxPackage -AllUsers | ft name,signaturekind,status,version,installlocation -Wrap -AutoSize > AppInfo.txt

#endregion

#region ProgramInfo

Write-Verbose "Writing Installed Program Info..."

$temp1 = gp HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*

$temp2 = gp HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*

$temp3 = gp HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*

$temp = $temp1 + $temp2 + $temp3

$temp | sort displayName | ft -Property DisplayName,DisplayVersion,Publisher,InstallDate > ProgramInfo.txt

#endregion

#region EnvInfo

ls env: | ft -Wrap -AutoSize > EnvInfo.txt

#endregion

#region NetworkInfo

Write-Verbose "Writing Network Info..."

netstat -aob > NetworkInfo.txt

#endregion

#region FileIntegrity 

if($SysFileHashes) {

Write-Verbose "Writing System File Hashes..."

ls c:\windows\system32 -Recurse 2> HashErrors.txt | Get-FileHash -Algorithm MD5 2>> HashErrors.txt | epcsv -Path ("SysFileHashes.csv") 

$exist = 1

}

#endregion

cd $curFolder

#region Report

$fname = 'WinSBL_' + $env:COMPUTERNAME + '_Report.htm'

'<!DOCTYPE html><html><body><style>table, th, td {border: 1px solid black;border-collapse: collapse;padding: 15px;}' > $fname
'</style></head><body><h2>Get-Security Baseline</h2><table style="width:100%"><tr><th>File Name</th><th>Description</th></tr>' >> $fname
'<tr><td><a href="' + $outFolder + '\ComputerInfo.txt">ComputerInfo</a></td><td>Standard System Information</td></tr>' >> $fname
'<tr><td><a href="' + $outFolder + '\UserInfo.txt">UserInfo</a></td><td>All Users Information</td></tr>' >> $fname
'<tr><td><a href="' + $outFolder + '\ServicesInfo.txt">ServicesInfo</a></td><td>System Services Information</td></tr>' >> $fname
'<tr><td><a href="' + $outFolder + '\SchTasksInfo.txt">SchTasksInfo</a></td><td>List of all Scheduled Tasks</td></tr>' >> $fname
'<tr><td><a href="' + $outFolder + '\MachineCertInfo.txt">MachineCertInfo</a></td><td>List of Installed Machine Certificates</td></tr>' >> $fname
'<tr><td><a href="' + $outFolder + '\UserCertInfo.txt">UserCertInfo</a></td><td>List of Installed User Certificates</td></tr>' >> $fname
'<tr><td><a href="' + $outFolder + '\AutoRunInfo_Ser.txt">AutoRunInfo_Ser</a></td><td>All Services set for Autorun</td></tr>' >> $fname
'<tr><td><a href="' + $outFolder + '\AutoRunInfo_SchTasks.txt">AutoRunInfo_SchTasks</a></td><td>All Scheduled Tasks set for Autorun</td></tr>' >> $fname
'<tr><td><a href="' + $outFolder + '\AutoRunInfo_Prog.txt">AutoRunInfo_Prog</a></td><td>All Programs set for Autorun</td></tr>' >> $fname
'<tr><td><a href="' + $outFolder + '\ProcessInfo.txt">ProcessInfo</a></td><td>List of all the Processes</td></tr>' >> $fname
'<tr><td><a href="' + $outFolder + '\DriverInfo.txt">DriverInfo</a></td><td>List of all the Installed Drivers</td></tr>' >> $fname
'<tr><td><a href="' + $outFolder + '\GPOInfo.txt">GPOInfo</a></td><td>List of all Local Group Policies</td></tr>' >> $fname
'<tr><td><a href="' + $outFolder + '\FirewallInfo.txt">FirewallInfo</a></td><td>Firewall Status and Rules</td></tr>' >> $fname
'<tr><td><a href="' + $outFolder + '\HardwareInfo.txt">HardwareInfo</a></td><td>System Hardware, Bitlocker and Active USB drives Information</td></tr>' >> $fname
'<tr><td><a href="' + $outFolder + '\AppInfo.txt">AppInfo</a></td><td>List of all the Installed Windows App</td></tr>' >> $fname
'<tr><td><a href="' + $outFolder + '\ProgramInfo.txt">ProgramInfo</a></td><td>List of all the Installed Programs</td></tr>' >> $fname
'<tr><td><a href="' + $outFolder + '\EnvInfo.txt">EnvInfo</a></td><td>Environment Variables List</td></tr>' >> $fname
'<tr><td><a href="' + $outFolder + '\NetworkInfo.txt">NetworkInfo</a></td><td>All Network Ports and Connections</td></tr>' >> $fname

If ($exist -eq "1")
{

'<tr><td><a href="' + $outFolder + '\SysFileHashes.csv">SysFileHashes</a></td><td>Hash of all files under System32</td></tr>' >> $fname

}

'</table></body></html><br/><br/>' >> $fname

'MIT License<br/><br/>Copyright (c) 2018 Abhijeet Jain<br/><br/>' >> $fname
'Permission is hereby granted, free of charge, to any person obtaining a copy<br/>' >> $fname
'of this software and associated documentation files (the "Software"), to deal<br/>' >> $fname
'in the Software without restriction, including without limitation the rights<br/>' >> $fname
'to use, copy, modify, merge, publish, distribute, sublicense, and/or sell<br/>' >> $fname
'copies of the Software, and to permit persons to whom the Software is<br/>' >> $fname
'furnished to do so, subject to the following conditions:<br/><br/>' >> $fname
'The above copyright notice and this permission notice shall be included in all<br/>' >> $fname
'copies or substantial portions of the Software.<br/><br/>' >> $fname
'THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR<br/>' >> $fname
'IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,<br/>' >> $fname
'FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE<br/>' >> $fname
'AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER<br/>' >> $fname
'LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,<br/>' >> $fname
'OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.' >> $fname

Write-Output "Thank you for using WinSBL - The report " + $fname +" has been generated under the current folder"

#endregion






