function Invoke-Sharky {
  [CmdletBinding()]
  Param()

  function Header {
    param(
      [string]$Line="---------------------------------------------------------------------",
      [string]$Title=""
    )
    Write-Output $Line
    Write-Output " $Title"
    Write-Output $Line
  }

  function Banner() {
    Write-Output "
                ____  _                _
               / ___|| |__   __ _ _ __| | ___   _
               \___ \| '_ \ / _`` | '__| |/ / | | |
                ___) | | | | (_| | |  |   <| |_| |
               |____/|_| |_|\__,_|_|  |_|\_\\__, |
                                             |___/ "
    Write-Output "---------------------------------------------------------------------"
    # Write-ColorOutput -ForegroundColor Green -Object "#" -NoNewline
    Write-Output "# Invoke-Sharky"
    # Write-ColorOutput -ForegroundColor Green -Object "#" -NoNewline
    Write-Output "# Windows Enumeration Script"
    # Write-ColorOutput -ForegroundColor Green -Object "#" -NoNewline
    Write-Output "# Written by: Drake Axelrod"
    Write-Output "# Inspired by: https://github.com/Hacker22o2/Basic-windows-enumeration"
    Write-Output "---------------------------------------------------------------------"
  }

  function FindPSHistories {
    $users = Get-ChildItem -Path "C:\Users" -Directory
    foreach ($user in $users) {
      $historyFile = Join-Path -Path $user.FullName -ChildPath "AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt"
      Write-Output ""
      if (-not (Test-Path $historyFile)) {
        Write-Output "[*] User: $($user.Name)"
        Write-Output "[*] No history found"
      } else {
        Write-Output "[*] User: $($user.Name)"
        Write-Output "[*] Path: $historyFile"
        Write-Output "[*] Content Below:"
        Write-Output ""
        Write-Output (Get-Content $historyFile)
      }
      Write-Output ""
    }
  }

# Folder: \PowerToys
# TaskName:                             \PowerToys\Autorun for Drake
# Status:                               Ready
# Next Run Time:                        N/A
# Last Run Time:                        11/30/1999 12:00:00 AM
# Last Result:                          267011
# Author:                               MACHINE\Drake
# Task To Run:                          C:\Program Files\PowerToys\PowerToys.exe
# Scheduled Task State:                 Enabled
# Run As User:                          Drake
# Schedule Type:                        At logon time

# schtasks /query /fo CSV /v | ConvertFrom-Csv | Select-Object TaskName,Author,Status,"Scheduled Task State","Schedule Type","Run As User","Next Run Time","Last Run Time","Last Result","Task To Run"

  # Get-Process | select Name, Path, Company, Description, Product, ProductVersion, FileVersion, StartTime, @{Name="Owner";Expression={(Get-WmiObject -Class Win32_Process -Filter "ProcessId = $($_.Id)").GetOwner().User}}

  # ============================== #
  # = Commands
  # ============================== #
  $standard = [ordered]@{
    'Basic System Information'                                                = 'systeminfo.exe /S $env:computername /FO LIST | Format-Table -AutoSize';
    'Find PowerShell Histories'                                               = 'FindPSHistories';
    'Environment Variables'                                                   = 'Get-ChildItem Env: | Format-Table Key,Value -AutoSize ';
    'User Privileges'                                                         = 'whoami /priv | Format-Table -Autosize';
    'Credential Manager'                                                      = 'cmdkey /list | Format-Table -AutoSize';
    # 'Folders and Files in User Directories Results'                           = 'tree /F /A C:\Users'
    # 'Folders and Files in C:\ Directories Results'                            = 'Get-ChildItem C:\ | Format-Table -AutoSize'; Name'
    'Folders with Everyone Permissions'                                       = 'Get-ChildItem "C:\Program Files\*", "C:\Program Files (x86)\*" | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match "Everyone"} } catch {}} | Format-Table -AutoSize';
    'Folders with BUILTIN User Permissions'                                   = 'Get-ChildItem "C:\Program Files\*", "C:\Program Files (x86)\*" | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match "BUILTIN\Users"} } catch {}} | Format-Table -AutoSize';
    'Network Information'                                                     = 'Get-NetIPConfiguration -Detailed -All'
    'DNS Servers'                                                             = 'Get-DnsClientServerAddress -AddressFamily IPv4 | ft';
    'ARP cache'                                                               = 'Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,LinkLayerAddress,State';
    'Routing Table'                                                           = 'Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex';
    'Network Connections'                                                     = 'netstat -ano | ft';
    'Connected Drives'                                                        = 'Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft';
    'Firewall Config'                                                         = 'netsh firewall show config | ft';
    'Local Users'                                                             = 'Get-LocalUser | Format-Table -AutoSize';
    'Local Groups'                                                            = 'Get-LocalGroup | Format-Table -AutoSize';
    'Local Administrators'                                                    = 'Get-LocalGroupMember -Group Administrators | Format-Table -AutoSize';
    # 'Running Processes'                                                       = 'Get-Process | select Name, Path, Company, Description, Product, ProductVersion, FileVersion, StartTime, @{Name="Owner";Expression={(Get-WmiObject -Class Win32_Process -Filter "ProcessId = $($_.Id)").GetOwner().User}} | ft';
    'Running Processes'                                                       = 'Get-Process | where {$_.ProcessName -notlike "svchost*"} | Format-Table -AutoSize';
    'Scheduled Tasks'                                                         = 'schtasks /query /fo CSV /v | ConvertFrom-Csv | Select-Object TaskName,Author,Status,"Scheduled Task State","Schedule Type","Run As User","Next Run Time","Last Run Time","Last Result","Task To Run"';
    'Services'                                                                = 'Get-Service | Format-Table -AutoSize';
    'User Autologon Registry Items'                                           = 'Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon" | select "Default*" | ft';
    'Software in Registry'                                                    = 'Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | Format-Table -AutoSize';
    'Drivers'                                                                 = 'driverquery.exe /v /fo csv | ConvertFrom-CSV | Select-Object "Display Name","Start Mode","State","Status","Path","Service Name" | Format-Table -AutoSize';

  }
# Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue

  function Setup {
    if (-not (Test-Path "C:\Workspace")) {
      New-Item -Path "C:\Workspace" -ItemType Directory
    }
    if (-not (Test-Path "C:\Workspace\Sharky")) {
      New-Item -Path "C:\Workspace\Sharky" -ItemType Directory
    }
  }

  function CleanUp {
    # Archive the results
    Compress-Archive -Path "C:\Workspace\Sharky\*" -DestinationPath "C:\Workspace\Sharky.zip"
    Remove-Item -Path "C:\Workspace\Sharky" -Recurse -Force
  }


  function RunCommands($commands) {
    ForEach ($command in $commands.GetEnumerator()) {
      # Header -Title $command.Key
      Invoke-Expression -Command $command.Value | Out-File -FilePath "C:\Workspace\Sharky\$($command.Key).txt"
    }
  }

  function Main {
    Setup
    Banner
    RunCommands($standard)
    CleanUp
    Write-Output "Results saved to: C:\Workspace\Sharky.zip"
  }

  Main
}