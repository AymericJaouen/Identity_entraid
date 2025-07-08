<#
.SYNOPSIS
Audits Microsoft Entra ID (formerly Azure AD) for human identities and Entra-native applications, including sign-in activity, app registrations, service principals, and managed identities.

.DESCRIPTION
This script provides a comprehensive identity audit of a Microsoft Entra ID tenant. It:
- Counts enabled users and categorizes them by sign-in activity
- Detects potential service accounts based on naming patterns
- Tallies applications, enterprise apps, and managed identities
- Supports summary or domain-based grouping
- Outputs results to a timestamped CSV report for governance and review

.PARAMETER UserServiceAccountNamesLike
An array of wildcard string patterns (e.g., 'svc-', 'bot-', 'app-') used to flag accounts that look like service users.

.PARAMETER Mode
Specifies the output format:
- 'ByDomain': Report grouped by domain suffix (e.g., @contoso.com)
- 'Summary': One-line tenant-wide total

.PARAMETER DaysInactive
Number of days since last sign-in to consider a user "inactive" (default = 180).

.EXAMPLE
.\Entra-Audit.ps1 -UserServiceAccountNamesLike "svc-", "bot-" -Mode Summary -DaysInactive 120

.EXAMPLE
.\Entra-Audit.ps1 -Mode ByDomain

.OUTPUTS
CSV files containing a user identity and app inventory snapshot under ./EntraReports/<timestamp>.

.NOTES
Author: Aymeric Jaouen  
Adapted from legacy Active Directory audit tooling to support Microsoft Entra-native APIs using Microsoft Graph SDK.

#>

param (
    [string[]]$UserServiceAccountNamesLike = @(),
    [ValidateSet("ByDomain", "Summary")]
    [string]$Mode = "ByDomain",
    [int]$DaysInactive = 180
)


# === Logging Setup ===
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$outputPath = ".\EntraReports"
if (-not (Test-Path $outputPath)) { New-Item -Path $outputPath -ItemType Directory | Out-Null }

$logPath = Join-Path $outputPath "EntraAudit_$timestamp.log"
function Write-Log {
    param (
        [string]$Message,
        [string]$Level = "INFO"
    )
    $formatted = "[{0}] [{1}] {2}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Level, $Message
    Add-Content -Path $logPath -Value $formatted
    Write-Host $Message
}

# === Initialization ===
function Initialize-EntraPrerequisites {
    $requiredPSVersion = [Version]"5.1"
    $requiredModules = @(
        "Microsoft.Graph.Users",
        "Microsoft.Graph.Applications",
        "Microsoft.Graph.Identity.DirectoryManagement"
    )

    if ($PSVersionTable.PSVersion -lt $requiredPSVersion) {
        Write-Log "PowerShell $requiredPSVersion or higher is required. Current version: $($PSVersionTable.PSVersion)" "ERROR"
        exit 1
    }

    foreach ($module in $requiredModules) {
        try {
            if (-not (Get-Module -ListAvailable -Name $module)) {
                Write-Log "Module '$module' not found. Installing it..." "WARNING"
                Install-Module $module -Scope CurrentUser -Force
            }
            Import-Module $module -ErrorAction Stop
            Write-Log "Successfully imported module '$module'." "INFO"
        } catch {
            Write-Log "Failed to import module '$module'. Ensure it's installed and accessible. $_" "ERROR"
            exit 1
        }
    }

    try {
        Connect-MgGraph -Scopes "User.Read.All", "Directory.Read.All", "Application.Read.All", "AuditLog.Read.All"
        if (-not (Get-MgContext)) {
            Write-Log "Login cancelled or authentication failed. Graph session not established." "ERROR"
            exit 1
        } else {
            Write-Log "Connected to Microsoft Graph successfully." "INFO"
        }
    } catch {
        Write-Log "An error occurred while trying to connect to Microsoft Graph. $_" "ERROR"
        exit 1
    }

    # Preserve and enforce culture for consistency
    $script:OriginalCulture = [System.Globalization.CultureInfo]::CurrentCulture
    $script:OriginalUICulture = [System.Globalization.CultureInfo]::CurrentUICulture
    [System.Threading.Thread]::CurrentThread.CurrentCulture = 'en-US'
    [System.Threading.Thread]::CurrentThread.CurrentUICulture = 'en-US'

    Write-Log "Entra ID prerequisites validated. Environment initialized." "INFO"
}

# Initialize prerequisites
Initialize-EntraPrerequisites

# === Paging for Users ===
Write-Log "Fetching Microsoft Entra users..." "INFO"
$allUsers = @()
$page = Get-MgUser -All -Property DisplayName, UserPrincipalName, AccountEnabled, SignInActivity |
    Select-Object DisplayName, UserPrincipalName, AccountEnabled,
        @{Name="LastSignInDate";Expression={$_.SignInActivity.LastSignInDateTime}}

do {
    $allUsers += $page
    $nextLink = $page.AdditionalProperties.'@odata.nextLink'
    if ($nextLink) {
        $page = Invoke-MgGraphRequest -Method GET -Uri $nextLink
    } else {
        break
    }
} while ($true)

# === User Audit Logic ===
$summary = @()

Write-Log "Fetching registered applications..."
$applications = Get-MgApplication -All | Select-Object DisplayName, AppId

Write-Log "Fetching enterprise applications (service principals)..."
$servicePrincipals = Get-MgServicePrincipal -All | Select-Object DisplayName, AppId, AccountEnabled

Write-Log "Fetching Managed Identities..."
$ManagedIdentity = Get-MgServicePrincipal -Filter "servicePrincipalType eq 'ManagedIdentity'"

# Region: User Audit Logic
$cutoff = (Get-Date).AddDays(-$DaysInactive)

foreach ($user in $allUsers) {
    $domain = ($user.UserPrincipalName -split "@")[1]
    $entry = $summary | Where-Object { $_.Domain -eq $domain }

    if (-not $entry) {
        $entry = [PSCustomObject]@{
            Domain                   = $domain
            TotalUsers               = 0
            ActiveUsers              = 0
            InactiveUsers            = 0
            NeverLoggedInUsers       = 0
            PatternMatchedUsers      = 0
            Applications             = 0
            EnterpriseApps           = 0
            ManagedIdentities        = 0
        }
        $summary += $entry
    }

    $entry.TotalUsers++

    if ($user.LastSignInDate) {
        if ($user.LastSignInDate -ge $cutoff) {
            $entry.ActiveUsers++
        } else {
            $entry.InactiveUsers++
        }
    } else {
        $entry.NeverLoggedInUsers++
    }

    if ($UserServiceAccountNamesLike | Where-Object { $user.UserPrincipalName -like "*$_*" }) {
        $entry.PatternMatchedUsers++
    }
}

# Add app stats / Managed Identities once per tenant
$tenantEntry = $summary | Sort-Object Domain | Select-Object -First 1
if ($tenantEntry) {
    $tenantEntry.Applications     = $applications.Count
    $tenantEntry.EnterpriseApps   = $servicePrincipals.Count
    $tenantEntry.ManagedIdentities = $ManagedIdentity.Count
}

# Region: Output
$fileName = "Entra_Audit_${Mode}_$timestamp.csv"
$fullExportPath = Join-Path -Path $outputPath -ChildPath $fileName

switch ($Mode) {
    "ByDomain" {
        Write-Log "Users by Domain Summary" -ForegroundColor Green
        $summary | Sort-Object Domain | Format-Table -AutoSize
        $summary | Export-Csv -Path $fullExportPath -NoTypeInformation -Encoding UTF8
    }
    "Summary" {
        $total = [PSCustomObject]@{
            TotalUsers            = ($summary | Measure-Object TotalUsers -Sum).Sum
            ActiveUsers           = ($summary | Measure-Object ActiveUsers -Sum).Sum
            InactiveUsers         = ($summary | Measure-Object InactiveUsers -Sum).Sum
            NeverLoggedInUsers    = ($summary | Measure-Object NeverLoggedInUsers -Sum).Sum
            PatternMatchedUsers   = ($summary | Measure-Object PatternMatchedUsers -Sum).Sum
            Applications          = $applications.Count
            EnterpriseApps        = $servicePrincipals.Count
            ManagedIdentities     = $ManagedIdentity.Count
        }
        $total | Format-Table
        $total | Export-Csv -Path $fullExportPath -NoTypeInformation -Encoding UTF8
    }
}

Write-Log "Report saved to: $fullExportPath" -ForegroundColor Cyan

# Reset culture
[System.Threading.Thread]::CurrentThread.CurrentCulture = $OriginalCulture
[System.Threading.Thread]::CurrentThread.CurrentUICulture = $OriginalUICulture
