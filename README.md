🔍 Microsoft Entra ID Human Identity & Application Inventory
This PowerShell script audits Microsoft Entra ID (formerly Azure AD) to extract and summarize human identities, registered applications, enterprise apps, and managed identities. It’s designed as an Entra-native rewrite of traditional Active Directory audit scripts, with modern Graph API support and flexible reporting options.

✨ Features
Counts and categorizes:
Enabled user accounts
Sign-in activity and account age
Pattern-matching on service-style usernames (e.g. svc-*)
App registrations (Applications)
Enterprise Applications (Service Principals)
Managed Identities (user-assigned + system-assigned)

Supports:
Domain-level or summary-level reports
CSV exports with timestamps
Culture consistency (for script stability across systems)

🚀 Requirements
PowerShell 5.1+
Microsoft Graph PowerShell SDK:

powershell
Install-Module Microsoft.Graph -Scope CurrentUser

🔑 Required Graph Permissions
The script requires delegated permissions (you will be prompted to sign in):
User.Read.All
Directory.Read.All
Application.Read.All
AuditLog.Read.All

> Your account should have Global Reader or higher privileges in Entra ID.

📥 Usage
powershell
.\Get-EntraHumanIdentity.ps1 `
    -UserServiceAccountNamesLike "svc-", "bot-", "app-" `
    -Mode ByDomain `
    -DaysInactive 180

Parameters
Parameter	Description
-UserServiceAccountNamesLike	Patterns to detect pseudo–service accounts among users.
-Mode	Either ByDomain or Summary
-DaysInactive	Threshold for flagging inactive user accounts

📦 Output
CSV report is saved to .\EntraReports\Entra_Audit_<timestamp>.csv
Includes counts by domain or tenant-wide summary
Fields: TotalUsers, Active, Inactive, NeverLoggedIn, Applications, Enterprise Apps, Managed Identities
