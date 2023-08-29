#
# Scan for GhostScript Files affected to CVE-2023-36664
#
# Version: 
#   1.3
# Date:
#   29.08.2023
# Author:
#   Winkler, Lars
#

# List all FileSystem without Network
$Path=([IO.DriveInfo]::getdrives() | ? {$_.DriveType -ne 'Network' -and $_.TotalSize -ne $null}).Name
# Source https://www.bsi.bund.de/SharedDocs/Cybersicherheitswarnungen/DE/2023/2023-248889-1012.html
$Files=(
  'gswin32c.exe', 'gswin64c.exe',
  'gswin32.exe', 'gswin64.exe',
  'gsdll32.dll', 'gsdll64.dll'
  )

# Self-elevate the script if required
if (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
 if ([int](Get-CimInstance -Class Win32_OperatingSystem | Select-Object -ExpandProperty BuildNumber) -ge 6000) {
  $CommandLine = "-File `"" + $MyInvocation.MyCommand.Path + "`" " + $MyInvocation.UnboundArguments
  Start-Process -FilePath PowerShell.exe -Verb Runas -ArgumentList $CommandLine
  Exit
 }
}
# put your code below this line

Write-Host "Searching $Path for files ($Files) ..."

Get-ChildItem -Path $Path -Recurse -Force -File -ErrorAction SilentlyContinue -OutVariable Findings -Include $Files

Write-Host "`nList versions.`n10.02.2 and above are not affected to CVE-2023-36664`n"
ForEach ($f in $Findings) {
  Write-Host "$f ($((Get-Item $f.FullName).VersionInfo.FileVersion))"
}

Write-Host "`nPress Enter key to exit"
Read-Host