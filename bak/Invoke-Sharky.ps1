function Invoke-Sharky {
  <#
  .SYNOPSIS
  Invoke-Sharky is a Windows enumeration script that provides a overview of the system.

  .DESCRIPTION
  Invoke-Sharky is a Windows enumeration script that provides a overview of the system. It provides basic system information, created for use in the OSCP exam.

  .PARAMETER ModuleName
  The name you wish to give the module.  The root folder, manifest, and root loader will be named after the module.

  .PARAMETER Author
  Enter a name to be listed as the Author in the module manifest.

  .PARAMETER Description
  A short description of the module to be listed in the module manifest.

  .PARAMETER PowershellVersion
  The minimum version of Powershell supported by the module.  One of 2.0, 3.0 (the default), 4.0 or 5.0.

  .PARAMETER ModulesPath
  The full path to the directory you wish to develop the module in.  This is where the module structure will be created.
  Include a trailing \ or don't, it doesn't matter.

  .EXAMPLE
  New-PSModule.ps1 -ModuleName WackyRaces -Author 'Penelope Pitstop' -Description 'Win the wacky races' -PowershellVersion '4.0' -ModulesPath 'c:\development\powershell-modules'
  Creates a new module structure called WackyRaces in c:\development\powershell-modules\WackyRaces.  The module manifest will require Powershell v4.0.
  #>

  [CmdletBinding()]
  Param(
    [String]$Output=""
  )
  # ============================== #
  # = Helper Functions
  # ============================== #

  function Write-ColorOutput {
      [CmdletBinding()]
      Param(
          [Parameter(Mandatory=$False,Position=1,ValueFromPipeline=$True,ValueFromPipelinebyPropertyName=$True)][Object] $Object,
          [Parameter(Mandatory=$False,Position=2,ValueFromPipeline=$True,ValueFromPipelinebyPropertyName=$True)][ConsoleColor] $ForegroundColor,
          [Parameter(Mandatory=$False,Position=3,ValueFromPipeline=$True,ValueFromPipelinebyPropertyName=$True)][ConsoleColor] $BackgroundColor,
          [Switch]$NoNewline
      )
      # Save previous colors
      $previousForegroundColor = $host.UI.RawUI.ForegroundColor
      $previousBackgroundColor = $host.UI.RawUI.BackgroundColor
      # Set BackgroundColor if available
      if ($BackgroundColor -ne $null) {
        $host.UI.RawUI.BackgroundColor = $BackgroundColor
      }
      # Set $ForegroundColor if available
      if ($ForegroundColor -ne $null) {
        $host.UI.RawUI.ForegroundColor = $ForegroundColor
      }
      # Always write (if we want just a NewLine)
      if ($Object -eq $null) {
          $Object = ""
      }
      if ($NoNewline) {
        [Console]::Write($Object)
      } else {
        Write-Output $Object
      }
      # Restore previous colors
      $host.UI.RawUI.ForegroundColor = $previousForegroundColor
      $host.UI.RawUI.BackgroundColor = $previousBackgroundColor
  }

  function Header {
    param(
      [string]$Line="---------------------------------------------------------------------",
      [string]$Title=""
    )
    Write-ColorOutput -ForegroundColor Blue -Object $Line
    Write-ColorOutput -ForegroundColor Magenta -Object " $Title"
    Write-ColorOutput -ForegroundColor Blue -Object $Line
  }

  function Banner() {
    Write-ColorOutput -ForegroundColor Magenta -Object "
                ____  _                _
               / ___|| |__   __ _ _ __| | ___   _
               \___ \| '_ \ / _`` | '__| |/ / | | |
                ___) | | | | (_| | |  |   <| |_| |
               |____/|_| |_|\__,_|_|  |_|\_\\__, |
                                             |___/ "
    Write-ColorOutput -ForegroundColor Blue -Object "
---------------------------------------------------------------------"
    # Write-ColorOutput -ForegroundColor Green -Object "#" -NoNewline
    Write-ColorOutput -ForegroundColor Magenta -Object "# Invoke-Sharky"
    # Write-ColorOutput -ForegroundColor Green -Object "#" -NoNewline
    Write-ColorOutput -ForegroundColor Magenta -Object "# Windows Enumeration Script"
    # Write-ColorOutput -ForegroundColor Green -Object "#" -NoNewline
    Write-ColorOutput -ForegroundColor Magenta -Object "# Written by: Drake Axelrod"
    # Write-ColorOutput -ForegroundColor Magenta -Object "# Inspired by: https://github.com/Hacker22o2/Basic-windows-enumeration"
    Write-ColorOutput -ForegroundColor Blue -Object "---------------------------------------------------------------------"
  }

  function FindPSHistories {
    $users = Get-ChildItem -Path "C:\Users" -Directory
    foreach ($user in $users) {
      $historyFile = Join-Path -Path $user.FullName -ChildPath "AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt"
      Write-ColorOutput -Object ""
      if (-not (Test-Path $historyFile)) {
        Write-ColorOutput -ForegroundColor Green -Object "[*] User: $($user.Name)"
        Write-ColorOutput -ForegroundColor Green -Object "[*] No history found"
      } else {
        Write-ColorOutput -ForegroundColor Green -Object "[*] User: $($user.Name)"
        Write-ColorOutput -ForegroundColor Green -Object "[*] Path: $historyFile"
      }
      Write-ColorOutput -Object ""
    }
  }

  function RunCommands($commands) {
    foreach ($command in $commands.GetEnumerator()) {

        Header -Title $Command.Name
        Invoke-Expression $command.Value

    }
  }

  # ============================== #
  # = Variables
  # ============================== #

  $commands = [ordered]@{}
  $ComputerName = $env:computername
  $OS = (Get-WmiObject -Class Win32_OperatingSystem -ComputerName $ComputerName | select caption | select-string windows)-split("=", "}", "{")[0] -replace "}"| select-string windows

  # ============================== #
  # = Basic Commands
  # ============================== #
  # # Basic System Information
  # $commands.Add('Basic System Information Results', 'Start-Process "systeminfo" -NoNewWindow -Wait | ft')
  # Environment Variables
  # $commands.Add('Environment Variables Results', 'Get-ChildItem Env: | ft Key,Value')
  # # Network Information
  # $commands.Add('Network Information Results', 'Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address')
  # # DNS Servers
  # $commands.Add('DNS Servers Results', 'Get-DnsClientServerAddress -AddressFamily IPv4 | ft')
  # # ARP cache
  # $commands.Add('ARP cache Results', 'Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,LinkLayerAddress,State')
  # # Routing Table
  # $commands.Add('Routing Table Results', 'Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex')
  # # Network Connections
  # $commands.Add('Network Connections Results', 'Start-Process "netstat" -ArgumentList "-ano" -NoNewWindow -Wait | ft')
  # # Connected Drives
  # $commands.Add('Connected Drives Results', 'Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft')
  # # Firewall Config
  # $commands.Add('Firewall Config Results', 'Start-Process "netsh" -ArgumentList "firewall show config" -NoNewWindow -Wait | ft')
  # # Credential Manager
  # $commands.Add('Credential Manager Results', 'start-process "cmdkey" -ArgumentList "/list" -NoNewWindow -Wait | ft')
  # # User Autologon Registry Items
  # $commands.Add('User Autologon Registry Items Results', 'Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon" | select "Default*" | ft')
  # # Local Groups
  # $commands.Add('Local Groups Results', 'Get-LocalGroup | ft Name')
  # # Local Administrators
  # $commands.Add('Local Administrators Results', 'Get-LocalGroupMember Administrators | ft Name, PrincipalSource')
  # # User Directories
  # $commands.Add('User Directories Results', 'Get-ChildItem C:\Users | ft Name')
  # # Searching for SAM backup files
  # $commands.Add('Searching for SAM backup files Results', 'Test-Path %SYSTEMROOT%\repair\SAM ; Test-Path %SYSTEMROOT%\system32\config\regback\SAM')
  # # Installed Software Directories
  # $commands.Add('Installed Software Directories Results', 'Get-ChildItem "C:\Program Files", "C:\Program Files (x86)" | ft Parent,Name,LastWriteTime')
  # # Software in Registry
  # $commands.Add('Software in Registry Results', 'Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name')
  # # Folders with Everyone Permissions
  # $commands.Add('Folders with Everyone Permissions Results', 'Get-ChildItem "C:\Program Files\*", "C:\Program Files (x86)\*" | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match "Everyone"} } catch {}} | ft')
  # # Folders with BUILTIN\User Permissions
  # $commands.Add('Folders with BUILTIN\User Permissions Results', 'Get-ChildItem "C:\Program Files\*", "C:\Program Files (x86)\*" | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match "BUILTIN\Users"} } catch {}} | ft')
  # # Checking registry for AlwaysInstallElevated
  # $commands.Add('Checking registry for AlwaysInstallElevated Results', 'Test-Path -Path "Registry::HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Installer" | ft')
  # # Unquoted Service Paths
  # $commands.Add('Unquoted Service Paths Results', 'gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike ''"*''} | select PathName, DisplayName, Name | ft')
  # # Scheduled Tasks
  # $commands.Add('Scheduled Tasks Results', 'Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State')
  # # Tasks Folder
  # $commands.Add('Tasks Folder Results', 'Get-ChildItem C:\Windows\Tasks | ft')
  # # Startup Commands
  # $commands.Add('Startup Commands Results', 'Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl')
  # # Host File content
  # $commands.Add('Host File content Results', 'Get-content $env:windir\System32\drivers\etc\hosts | out-string')
  # # Running Services
  # $commands.Add('Running Services Results', 'Get-service | Select Name,DisplayName,Status | sort status | Format-Table -Property * -AutoSize | Out-String -Width 4096')
  # # Installed Softwares in Computer
  # $commands.Add('Installed Softwares in Computer Results', 'Get-wmiobject -Class win32_product | select Name, Version, Caption | ft -hidetableheaders -autosize| out-string -Width 4096')
  # # Installed Patches
  # $commands.Add('Installed Patches Results', 'Get-Wmiobject -class Win32_QuickFixEngineering -namespace "root\cimv2" | select HotFixID, InstalledOn| ft -autosize | out-string')
  # # Recent Documents Used
  # $commands.Add('Recent Documents Used Results', 'get-childitem "C:\Users\$env:username\AppData\Roaming\Microsoft\Windows\Recent"  -EA SilentlyContinue | select Name | ft -hidetableheaders | out-string')
  # # Potentially Interseting files
  # $commands.Add('Potentially Interseting files Results', 'get-childitem "C:\Users\" -recurse -Include *.zip,*.rar,*.7z,*.gz,*.conf,*.rdp,*.kdbx,*.crt,*.pem,*.ppk,*.txt,*.xml,*.vnc.*.ini,*.vbs,*.bat,*.ps1,*.cmd -EA SilentlyContinue | %{$_.FullName } | out-string | ft')
  # # Last 10 Modified items
  # $commands.Add('Last 10 Modified items Results', 'Get-ChildItem "C:\Users" -recurse -EA SilentlyContinue | Sort {$_.LastWriteTime} |  %{$_.FullName } | select -last 10 | ft -hidetableheaders | out-string')
  # # Stored Credentials
  # $commands.Add('Stored Credentials Results', 'cmdkey /list | out-string')
  # # Localgroup Administrators
  # $commands.Add('Localgroup Administrators Results', 'net localgroup Administrators')
  # # Current User
  # $commands.Add('Current User Results', 'Write-Host $env:UserDomain\$env:UserName')
  # # User Privileges
  # $commands.Add('User Privileges Results', 'start-process "whoami" -ArgumentList "/priv" -NoNewWindow -Wait | ft')
  # # Local Users
  # $commands.Add('Local Users Results', 'Get-LocalUser | ft Name,Enabled,LastLogon')
  # # Logged in Users
  # $commands.Add('Logged in Users Results', 'gcim Win32_LoggedOnUser  | ft')
  # # Running Processes
  # $commands.Add('Running Processes Results', 'gwmi -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize')

  # PERSONALLY ADDED / CHOSEN COMMANDS
  # Basic System Information
  $commands.Add('Basic System Information Results', 'systeminfo.exe /S $ComputerName /FO LIST | ft')
  # PowerShell Histories
  $commands.Add('Find PowerShell Histories', 'FindPSHistories')
  # User Directories
  $commands.Add('User Directories Results', 'Get-ChildItem C:\Users | ft Name')
  # ============================== #
  # = Active Directory Commands
  # ============================== #


  # ============================== #
  # = Main Function
  # ============================== #
  function Main() {
    Banner

    Write-ColorOutput -Object ""
    Write-ColorOutput -ForegroundColor Green -Object "[*] You ran this script on $(Get-Date)"
    Write-ColorOutput -Object ""

    RunCommands $commands
  }

  # ============================== #
  # = Execution
  # ============================== #
  if ($Output -eq "") {
    Main
  } else {
    Main | Out-File -FilePath $Output
  }
}
