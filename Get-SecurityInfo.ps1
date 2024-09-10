function Write-Info {
    param([string]$message)
    Write-Host $message -ForegroundColor Cyan
}

function Write-Warning {
    param([string]$message)
    Write-Host $message -ForegroundColor Yellow
}

function Write-Critical {
    param([string]$message)
    Write-Host $message -ForegroundColor Red
}

function Write-Safe {
    param([string]$message)
    Write-Host $message -ForegroundColor Green
}

# installed patches
function Get-PatchInfo {
    Write-Info "Installed Patches and Last Security Patch:"
    try {
        $patches = Get-HotFix
        if ($patches.Count -gt 0) {
            $lastPatch = $patches | Sort-Object InstalledOn -Descending | Select-Object -First 1
            Write-Host "Total Installed Patches: $($patches.Count)" -ForegroundColor Green
            Write-Host "Most Recent Patch: $($lastPatch.HotFixID) installed on $($lastPatch.InstalledOn)" -ForegroundColor Green
        } else {
            Write-Warning "No patches found!"
        }
    } catch {
        if ($VerbosePreference -eq 'Continue') {
            Write-Error "Failed to retrieve patch information. $_"
        }
    }
    Write-Host ""
}

# antivirus  details
function Get-SecurityAppInfo {
    Write-Info "Installed Security Applications (Antivirus/Defender):"
    try {
        $antivirus = Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct
        if ($antivirus) {
            $antivirus | ForEach-Object {
                Write-Host "Antivirus Product: $($_.displayName)" -ForegroundColor Green
                Write-Host "Product State: $($_.productState)" -ForegroundColor Green
            }
        } else {
            Write-Warning "No antivirus detected!"
        }
    } catch {
        if ($VerbosePreference -eq 'Continue') {
            Write-Error "Failed to retrieve antivirus information. $_"
        }
    }
    Write-Host ""
}

# Windows Defender details
function Get-DefenderInfo {
    Write-Info "Windows Defender Status:"
    try {
        $defender = Get-MpComputerStatus
        if ($defender.AntivirusEnabled) {
            Write-Safe "Windows Defender is Enabled"
            Write-Host "AMProductVersion: $($defender.AMProductVersion)" -ForegroundColor Green
            Write-Host "Antivirus Signature Last Updated: $($defender.AntivirusSignatureLastUpdated)" -ForegroundColor Green
        } else {
            Write-Critical "Windows Defender is Disabled"
        }
    } catch {
        if ($VerbosePreference -eq 'Continue') {
            Write-Error "Unable to retrieve Windows Defender status. $_"
        }
    }
    Write-Host ""
}

#  firewall status
function Get-FirewallInfo {
    Write-Info "Windows Firewall Status:"
    try {
        $firewallProfiles = Get-NetFirewallProfile
        $firewallProfiles | ForEach-Object {
            Write-Host "$($_.Name) Profile: Enabled=$($_.Enabled)" -ForegroundColor Green
        }
        if ($firewallProfiles | Where-Object { $_.Enabled -eq $false }) {
            Write-Critical "One or more firewall profiles are disabled!"
        }
    } catch {
        if ($VerbosePreference -eq 'Continue') {
            Write-Error "Failed to retrieve firewall status. $_"
        }
    }
    Write-Host ""
}

# security updates
function Get-SecurityUpdates {
    Write-Info "Security Updates:"
    try {
        $securityUpdates = Get-HotFix | Where-Object { $_.Description -eq "Security Update" }
        if ($securityUpdates.Count -gt 0) {
            Write-Host "Total Security Updates Installed: $($securityUpdates.Count)" -ForegroundColor Green
            $securityUpdates | ForEach-Object {
                Write-Host "KB: $($_.HotFixID) Installed on $($_.InstalledOn)" -ForegroundColor Green
            }
        } else {
            Write-Critical "No security updates installed!"
        }
    } catch {
        if ($VerbosePreference -eq 'Continue') {
            Write-Error "Failed to retrieve security updates. $_"
        }
    }
    Write-Host ""
}

# OS version
function Get-OSInfo {
    Write-Info "Operating System Information:"
    try {
        $os = Get-CimInstance -ClassName Win32_OperatingSystem
        Write-Host "OS Version: $($os.Caption)" -ForegroundColor Green
        Write-Host "Build Number: $($os.BuildNumber)" -ForegroundColor Green
        Write-Host "Architecture: $($os.OSArchitecture)" -ForegroundColor Green
    } catch {
        if ($VerbosePreference -eq 'Continue') {
            Write-Error "Failed to retrieve OS information. $_"
        }
    }
    Write-Host ""
}


# Privileged Accounts

function Get-UserAccounts {
    Write-Info "User Accounts and Privileges:"
    try {
        $users = Get-LocalUser
        $users | ForEach-Object {
            Write-Host "User: $($_.Name), Enabled: $($_.Enabled)" -ForegroundColor Green
        }
    } catch {
        if ($VerbosePreference -eq 'Continue') {
            Write-Error "Failed to retrieve user accounts. $_"
        }
    }
    Write-Host ""
}

function Get-AdminGroupMembers {
    Write-Info "Local Administrator Group Members:"
    try {
        $admins = Get-LocalGroupMember -Group "Administrators"
        $admins | ForEach-Object {
            Write-Host "Admin: $($_.Name)" -ForegroundColor Green
        }
    } catch {
        if ($VerbosePreference -eq 'Continue') {
            Write-Error "Failed to retrieve admin group members. $_"
        }
    }
    Write-Host ""
}


function Get-GroupsMembers {
    # Retrieve all local groups
    $groups = Get-LocalGroup
    
    # Iterate over each group
    foreach ($group in $groups) {

        Write-Host "Group: $($group.Name)" -ForegroundColor Cyan
        

        $members = Get-LocalGroupMember -Group $group.Name
        

        if ($members.Count -eq 0) {
            Write-Host "  No members found" -ForegroundColor Yellow
        } else {

            foreach ($member in $members) {

                $displayName = if ($member.Name) { $member.Name } else { $member.SID }
                $color = if ($member.PSObject.BaseObject.GetType().Name -eq 'LocalUser') { 'Green' } else { 'Magenta' }
                Write-Host "  Member: $displayName" -ForegroundColor $color
            }
        }

        Write-Host ""
    }
}

# Critical Service Status

function Get-ServiceStatus {
    Write-Info "Critical Services Status:"
    
    $services = @("TermService", "LanmanServer", "wuauserv", "WinRM", "Dnscache", "Netlogon", "KDC", "RemoteRegistry", "Spooler", "W32Time", "DNS", "Kerberos", "WINS", "W3SVC", "SMTPS", "FTP", "MySQL", "PostgreSQL", "NetBIOS", "LLMNR", "RPC", "RDP", "DHCP", "NTP", "IMAP", "POP3", "SNMP", "Telnet", "PowerShellRemoting", "MSRPC")


    foreach ($service in $services) {
        try {
            $serviceStatus = Get-Service -Name $service -ErrorAction Stop
            Write-Host "$($serviceStatus.Name) - Status: $($serviceStatus.Status)" -ForegroundColor Green
        } catch {
            if ($VerbosePreference -eq 'Continue') {
                Write-Error "Failed to retrieve status for service $service. $_"
            }
        }
    }
    Write-Host ""
}

# Security Policies

function Get-PasswordPolicy {
    Write-Info "Password Policy:"
    try {
        $policy = Get-LocalUser | Select-Object -First 1 | Get-LocalUser -Property PasswordNeverExpires, PasswordRequired, UserCannotChangePassword
        Write-Host "Password Policy - Password Never Expires: $($policy.PasswordNeverExpires)" -ForegroundColor Green
        Write-Host "Password Policy - Password Required: $($policy.PasswordRequired)" -ForegroundColor Green
        Write-Host "Password Policy - User Cannot Change Password: $($policy.UserCannotChangePassword)" -ForegroundColor Green
    } catch {
        if ($VerbosePreference -eq 'Continue') {
            Write-Error "Failed to retrieve password policy. $_"
        }
    }
    Write-Host ""
}

function Get-AuditPolicy {
    Write-Info "Audit Policy:"
    try {
        $auditPolicy = Get-WinEvent -LogName Security -MaxEvents 1
        Write-Host "Last Security Event ID: $($auditPolicy.Id)" -ForegroundColor Green
    } catch {
        if ($VerbosePreference -eq 'Continue') {
            Write-Error "Failed to retrieve audit policy. $_"
        }
    }
    Write-Host ""
}

#Network Configuration
function Get-OpenPorts {
    Write-Info "Open Network Ports:"
    try {
        $ports = Get-NetTCPConnection | Select-Object -Property LocalPort, State
        $ports | ForEach-Object {
            Write-Host "Port: $($_.LocalPort), State: $($_.State)" -ForegroundColor Green
        }
    } catch {
        if ($VerbosePreference -eq 'Continue') {
            Write-Error "Failed to retrieve open ports. $_"
        }
    }
    Write-Host ""
}

function Get-ActiveConnections {
    Write-Info "Active Network Connections:"
    try {
        $connections = Get-NetTCPConnection
        $connections | ForEach-Object {
            Write-Host "Local Address: $($_.LocalAddress):$($_.LocalPort) - Remote Address: $($_.RemoteAddress):$($_.RemotePort)" -ForegroundColor Green
        }
    } catch {
        if ($VerbosePreference -eq 'Continue') {
            Write-Error "Failed to retrieve active connections. $_"
        }
    }
    Write-Host ""
}


# Scheduled Tasks
function Get-ScheduledTasks {
    Write-Info "Scheduled Tasks:"
    try {
        $tasks = Get-ScheduledTask
        $tasks | ForEach-Object {
            $taskName = $_.TaskName
            $status = $_.State
            $taskPath = $_.Actions.Execute  # Path to the file or script being run
            $taskUser = $_.Principal.UserId  # Get the user who scheduled/runs the task
            
            # Remove extra quotes from taskPath if they exist
            $taskPath = $taskPath.Trim('"')

            # Resolve environment variables in taskPath (e.g., %systemroot%)
            $taskPath = [Environment]::ExpandEnvironmentVariables($taskPath)
            
            Write-Host "Task Name: $taskName, Status: $status, User: $taskUser" -ForegroundColor Green

            # Check if taskPath exists before attempting to get ACL
            if (Test-Path $taskPath) {
                # Get the ACL for the file and check if current user has write/read permissions
                $fileAcl = Get-Acl -Path $taskPath
                $permissions = $fileAcl.Access | Where-Object {
                    ($_.IdentityReference -eq $env:USERNAME) -and
                    ($_.FileSystemRights -match 'Write' -or $_.FileSystemRights -match 'Read')
                }

                if ($permissions) {
                    Write-Host "  - You have the following permissions on the file/folder: $($permissions.FileSystemRights)" -ForegroundColor Yellow
                } else {
                    Write-Host "  - No special permissions found." -ForegroundColor Red
                }
            } else {
                Write-Host "  - The task path '$taskPath' does not exist." -ForegroundColor DarkYellow
            }
        }
    } catch {
        if ($VerbosePreference -eq 'Continue') {
            Write-Error "Failed to retrieve scheduled tasks. $_"
        }
    }
    Write-Host ""
}


function Get-LocalAdmins {
    Write-Info "Local Administrators:"
    $admins = Get-LocalGroupMember -Group "Administrators"
    if ($admins) {
        $admins | ForEach-Object {
            Write-Host "Local Admin: $($_.Name)" -ForegroundColor Green
        }
    } else {
        Write-Warning "No local administrators found or unable to retrieve."
    }
    Write-Host ""
}


function Get-SystemUptime {
    Write-Info "System Uptime:"
    $uptime = (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime
    Write-Host "Last Boot Time: $uptime" -ForegroundColor Green
    Write-Host "Uptime: $(New-TimeSpan -Start $uptime)" -ForegroundColor Green
    Write-Host ""
}

function Get-EventLogs {
    Write-Info "Recent Event Logs:"
    try {
        $logs = Get-EventLog -LogName Security -Newest 20
        if ($logs) {

            $formattedLogs = $logs | ForEach-Object {

                $accountName = "N/A"
                $groupName = "N/A"
                $processName = "N/A"
                
                if ($_.Message -match "Account Name:\s*(\S+)") {
                    $accountName = $matches[1]
                }
                if ($_.Message -match "Group Name:\s*(.*)") {
                    $groupName = $matches[1]
                }
                if ($_.Message -match "Process Name:\s*(.*)") {
                    $processName = $matches[1]
                }

                [PSCustomObject]@{
                    EventID        = $_.EventID
                    TimeGenerated  = $_.TimeGenerated
                    AccountName    = $accountName
                    GroupName      = $groupName
                    ProcessName    = $processName
                    Message        = $_.Message
                }
            }

            $formattedLogs | ForEach-Object {
                Write-Host "Event ID: $($_.EventID)" -ForegroundColor Cyan
                Write-Host "Time: $($_.TimeGenerated)" -ForegroundColor Yellow
                Write-Host "Account Name: $($_.AccountName)" -ForegroundColor Magenta
                Write-Host "Group Name: $($_.GroupName)" -ForegroundColor Blue
                Write-Host "Process Name: $($_.ProcessName)" -ForegroundColor Green
                Write-Host "Message: $($_.Message)" -ForegroundColor Green
                Write-Host "" # Empty line for separation
            }
        } else {
            Write-Warning "No recent security event logs found."
        }
    } catch {
        if ($VerbosePreference -eq 'Continue') {
            Write-Error "Failed to retrieve event logs. $_"
        }
    }
    Write-Host ""
}

<#
# SystemFileIntegrity

function Check-SystemFileIntegrity {
    Write-Info "Checking System File Integrity:"
    try {
        sfc /scannow
    } catch {
        if ($VerbosePreference -eq 'Continue') {
            Write-Error "Failed to check system file integrity. $_"
        }
    }
    Write-Host ""
}
#>


# Main execution
Write-Host "Security Configuration Enumeration for Host" -ForegroundColor Cyan
Write-Host "-----------------------------------------" -ForegroundColor Cyan
Get-PatchInfo
Get-SecurityAppInfo
Get-DefenderInfo
Get-FirewallInfo
Get-SecurityUpdates
Get-OSInfo
Get-UserAccounts
Get-AdminGroupMembers
Get-GroupsMembers
Get-ServiceStatus
Get-PasswordPolicy
Get-AuditPolicy
Get-OpenPorts
Get-ActiveConnections
Get-ScheduledTasks
Get-LocalAdmins
Get-SystemUptime
Get-EventLogs
# Check-SystemFileIntegrity
Write-Host "-----------------------------------------" -ForegroundColor Cyan
Write-Host "Security Assessment Complete!" -ForegroundColor Cyan
