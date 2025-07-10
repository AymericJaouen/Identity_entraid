# 🔍 Microsoft Entra Audit Script

This PowerShell script audits a Microsoft Entra ID (formerly Azure AD) tenant to provide insight into user activity, service accounts, applications, and managed identities. It supports scalable enterprise deployment without requiring app registration.

---

## 📦 Features

- Audits user activity and last sign-in status
- Detects service accounts by naming patterns
- Counts registered apps, enterprise apps, and managed identities
- Generates domain-level or summary reports (CSV)
- Logs output to a timestamped log file
- Supports delegated authentication via Microsoft Graph PowerShell

---

## Getting Started

### Required Permissions

This script uses delegated Graph permissions:
- `User.Read.All`
- `Directory.Read.All`
- `Application.Read.All`
- `AuditLog.Read.All`

> Note: Some tenants may require **admin consent** for `offline_access` or audit scopes.

### Entra Roles Required

Assign one of the following to the executor:
- `Global Reader`
- `Reports Reader`
- `User Administrator`

---

## Usage

```powershell
.\EntraAudit.ps1 -UserServiceAccountNamesLike @("svc_", "robot", "admin") -Mode "ByDomain" -DaysInactive 180

Parameters
Parameter	Description
-UserServiceAccountNamesLike	Patterns to detect pseudo–service accounts among users.
-Mode	Either ByDomain or Summary
-DaysInactive	Threshold for flagging inactive user accounts

📄 Outputs
CSV Report saved to .\EntraReports
Log File with detailed timestamped entries saved to .\EntraReports

🧭 Consent Instructions
If the script shows:
“This application requires your administrator’s approval…”
Ask your admin to approve Graph SDK scopes via this link:
https://login.microsoftonline.com/<TenantID>/adminconsent?client_id=de8bc8b5-d9f9-48b1-a8ad-b748da725064

Alternatively, grant the user one of the roles listed above.

🧪 Troubleshooting
Ensure PowerShell ≥ 5.1
Run in elevated mode if installing modules
Check Get-MgContext before executing the script
For restricted tenants, use Connect-MgGraph interactively with minimal scopes
