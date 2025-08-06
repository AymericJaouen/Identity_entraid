# Entra Human Identity Audit Script

A powerful PowerShell script for auditing human identities and applications in a Microsoft Entra ID (formerly Azure AD) tenant. This tool provides a comprehensive overview of user activity, synchronization status, and application ownership in multiple output formats to help Rubrik SE understand your environnement

## ✨ Features

- **User Activity Metrics:** Categorizes users as active, inactive, or never logged in based on a configurable inactivity period.
- **Service Account Detection:** Flags potential service accounts using customizable wildcard naming patterns.
- **On-Premises Synchronization:** Identifies users synchronized from on-premises Active Directory and reports the source domain.
- **Application Ownership:** Audits user ownership of Enterprise Applications, Managed Identities, and App Registrations.
- **Flexible Reporting:** Generates multiple output formats to suit different needs:
    - **Summary:** A high-level, tenant-wide overview.
    - **By Domain:** A breakdown of user metrics grouped by email domain.
    - **By User:** A detailed, per-user report with all collected information.
    - **HTML:** A single, comprehensive HTML file combining all reports into a professional, easily shareable format.
- **Full Audit Mode:** The `Full` mode automates the generation of all available reports with a single command.

## 🚀 Getting Started

### Prerequisites

- PowerShell 5.1 or newer.
- An account with the necessary permissions in Microsoft Entra ID to read user and application data (e.g., Global Reader, Global Administrator, or a custom role with `User.Read.All`, `Directory.Read.All`, and `Application.Read.All` scopes).
- The `Microsoft.Graph` PowerShell modules (`Microsoft.Graph.Users`, `Microsoft.Graph.Applications`, `Microsoft.Graph.Identity.DirectoryManagement`). The script will attempt to install these automatically if they are missing.

### Installation

1.  Clone this repository or download the `Get-EntraHumanIdentity.ps1` script.
2.  Open PowerShell as an administrator.
3.  Set the execution policy to allow scripts: `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser`
4.  Navigate to the directory where the script is located.

### Usage

The script connects to your Microsoft Entra ID tenant using `Connect-MgGraph`. It will prompt you for authentication if a session is not already active.

```powershell
.\Get-EntraHumanIdentity.ps1 [-UserServiceAccountNamesLike <string[]>] [-Mode <string>] [-DaysInactive <int>]
Parameters
UserServiceAccountNamesLike: An array of wildcard patterns (e.g., 'svc-', 'app-') to flag accounts as potential service users.

Mode: Specifies the output format. Valid values are ByDomain, ByUser, Summary, Html, and Full. Defaults to ByDomain.

DaysInactive: The number of days after which a user with no sign-in activity is considered inactive. Defaults to 180.

💡 Examples
1. Generate a Summary Report with Custom Inactivity Period
This example creates a quick summary report and considers users inactive after 90 days of no sign-in.

PowerShell

.\Get-EntraHumanIdentity.ps1 -Mode Summary -DaysInactive 90
2. Generate a Detailed Per-User Report
This command creates a detailed CSV report for every user, including application ownership, and also flags accounts matching 'svc-' or 'bot-'.

PowerShell

.\Get-EntraHumanIdentity.ps1 -Mode ByUser -UserServiceAccountNamesLike "svc-", "bot-"
3. Generate a Comprehensive HTML Report
This generates a single HTML file that contains a summary table, a domain-based table, and a detailed user table.

PowerShell

.\Get-EntraHumanIdentity.ps1 -Mode Html
4. Run a Full Audit
This is the most comprehensive option, which generates all four reports (Summary, ByDomain, ByUser, and HTML) with a single command.

PowerShell

.\Get-EntraHumanIdentity.ps1 -Mode Full
📂 Output
All generated reports are saved in a subdirectory named EntraReports in the same location as the script. Each file is automatically timestamped for easy version control.

Entra_Audit_Summary_<timestamp>.csv

Entra_Audit_ByDomain_<timestamp>.csv

Entra_Audit_ByUser_<timestamp>.csv

Entra_Audit_Report_<timestamp>.html

📄 License
This project is licensed under the MIT License.