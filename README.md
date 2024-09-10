# Get-SecurityInfo


**Get-SecurityInfo** is a comprehensive PowerShell tool designed to gather critical security configuration details from Windows systems. This tool is perfect for security assessments and penetration testing, providing a wide array of system, network, and security-related information in a readable and structured format.

## Features

- **Patch Information**: Lists installed patches and the most recent security patch.
- **Antivirus and Defender Status**: Retrieves details on installed antivirus products and Windows Defender status.
- **Firewall Configuration**: Shows the status of the Windows Firewall across different profiles.
- **Security Updates**: Gathers installed security updates.
- **Operating System Information**: Displays OS version, build number, and architecture.
- **User Accounts and Group Memberships**: Lists local user accounts and members of critical groups like Administrators.
- **Critical Services Status**: Checks the status of important services such as RDP, SMB....
- **Password and Audit Policies**: Retrieves password policies and audit policies from the system.
- **Network Configuration**: Shows open network ports and active network connections.
- **Scheduled Tasks**: Retrieves details on scheduled tasks and checks for potential privilege escalation opportunities through file permissions.
- **Event Logs**: Displays the most recent security event logs.
- **System Uptime**: Shows system uptime and last boot time.

## Installation

1. Clone the repository:
    ```bash
    git clone https://github.com/yourusername/Get-SecurityInfo.git
    ```

2. Open a PowerShell session and navigate to the directory:
    ```bash
    cd Get-SecurityInfo
    ```

3. Run the script:
    ```powershell
    .\Get-SecurityInfo.ps1
    ```

## Usage

You can run the tool directly to collect information, or customize the execution by calling individual functions. Here's an example of how to gather patch and security information:

```powershell
Get-PatchInfo
Get-SecurityUpdates
Get-DefenderInfo
```

To retrieve details on network activity:

```powershell
Get-OpenPorts
Get-ActiveConnections
```

### Verbose Mode

To see detailed error messages, enable verbose mode by running:

```powershell
$VerbosePreference = 'Continue'
```

## Output

### Example Output
```
-----------------------------------------------------------
System Information:
-----------------------------------------------------------
Operating System:        Microsoft Windows 10 Pro
OS Build:                19042.1052
Architecture:            64-bit
-----------------------------------------------------------

-----------------------------------------------------------
Firewall Status:
-----------------------------------------------------------
Public Profile:          Enabled
Private Profile:         Disabled
Domain Profile:          Enabled
-----------------------------------------------------------

-----------------------------------------------------------
User Accounts and Group Memberships:
-----------------------------------------------------------
Administrator             Local Administrators Group
JohnDoe                   Local Administrators Group
-----------------------------------------------------------
```

### All output is color-coded for easy reading:

- **Cyan**: Information messages
- **Green**: Safe/Successful operations
- **Yellow**: Warnings
- **Red**: Critical issues/errors

## Contributing

Contributions, issues, and feature requests are welcome! Feel free to check the [issues page](https://github.com/Zyad-Elsayed/Get-SecurityInfo/issues).

## Disclaimer

This tool is intended for educational and security testing purposes only. Use it responsibly and ensure you have the necessary permissions when running it in production environments.
