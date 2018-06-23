# CreateWinSBL
This code is intended to assist with creating a Security baseline for a Windows OS. No installation needed. Supports Windows 8 / Server 2012 (Powershell 3) and above. 

This project was inspired by COPE.

Prerequisites:

- Work with SysInternal tools (included in the files)
- Require local admin rights
- Require modification to script execution policy for Powershell if enabled
- Requires at least Powershell 3 

Future updates to this script would include automatic file comparisons between the previous and current snapshot for each category.


.EXAMPLE
Get-SecurityBaseline.ps1 -output "C:\Temp"

Creates an output folder in the Temp directory under C Drive.

Get-SecurityBaseline.ps1 -SysFileHashes -Verbose

Generates System32 file hashes along with standard output. Prints Verbose messages.

.NOTES

Close all the programs before running the script for capturing only the essential data.
