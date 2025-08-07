<#
.SYNOPSIS
Audits Microsoft Entra ID (formerly Azure AD) for human identities, on-premises synchronization status, and Entra-native applications.

.DESCRIPTION
This script performs a comprehensive identity and application audit of a Microsoft Entra ID tenant. It connects to the Microsoft Graph API to retrieve and analyze data, including:
- Counting and categorizing users based on their last sign-in activity.
- Detecting potential service accounts based on custom naming patterns.
- Identifying users synchronized from on-premises Active Directory and their source domain.
- Auditing user ownership of applications, enterprise apps, and managed identities.
- Generating multiple report formats to suit different needs: a tenant-wide summary, a per-domain breakdown, a detailed per-user report, or a single comprehensive HTML file.

.PARAMETER UserServiceAccountNamesLike
An array of wildcard string patterns (e.g., 'svc-', 'bot-', 'app-') used to flag accounts that look like service users.

.PARAMETER Mode
Specifies the output format:
- 'ByDomain': A CSV report grouped by user domain suffix (e.g., @contoso.com). Export as HTML
- 'ByUser': A detailed CSV report for each user, including ownership details. Export as HTML
- 'Full': Generates all 2 reports (ByDomain, ByUser) as separate files. Export as HTML

.PARAMETER DaysInactive
Number of days since the last sign-in to consider a user "inactive." The default is 180 days.

.EXAMPLE
PS> .\Get-EntraHumanIdentity.ps1 -UserServiceAccountNamesLike "svc-", "bot-" -Mode Summary

Description: Generates a single CSV file with a tenant-wide summary, classifying users and providing application counts.

.EXAMPLE
PS> .\Get-EntraHumanIdentity.ps1 -Mode ByDomain -DaysInactive 90

Description: Creates a CSV report grouped by user domain, with users considered inactive if they haven't signed in for 90 days.

.EXAMPLE
PS> .\Get-EntraHumanIdentity.ps1 -Mode Full

Description: Generates all four report files (Summary.csv, ByDomain.csv, ByUser.csv, and Report.html) in the output directory.

.EXAMPLE
PS> .\Get-EntraHumanIdentity.ps1 -Mode Html

Description: Creates a single, comprehensive HTML report that includes all summary, domain, and user-level details.

.OUTPUTS
CSV and HTML files containing a user identity and application inventory snapshot under .\EntraReports\<timestamp>.

.NOTES
Author: Aymeric Jaouen
#>

param (
    [string[]]$UserServiceAccountNamesLike = @(),
    [ValidateSet("ByDomain", "ByUser", "Full")]
    [string]$Mode = "Full",
    [int]$DaysInactive = 180
)

# === Global Variables and Logging Setup ===
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$outputPath = ".\EntraReports"
if (-not (Test-Path $outputPath)) { New-Item -Path $outputPath -ItemType Directory | Out-Null }

$logPath = Join-Path $outputPath "EntraAudit_$timestamp.log"

function Write-Log {
    param (
        [string]$Message,
        [string]$Level = "INFO",
        [System.ConsoleColor]$Color = "White"
    )
    $formatted = "[{0}] [{1}] {2}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Level, $Message
    Add-Content -Path $logPath -Value $formatted
    Write-Host $Message -ForegroundColor $Color
}

# === Log the command that started the script ===
try {
    $commandString = $MyInvocation.MyCommand.Name
    foreach ($param in $MyInvocation.BoundParameters.GetEnumerator()) {
        $paramName = $param.Key
        $paramValue = $param.Value

        $formattedValue = ""
        if ($paramValue -is [System.Array]) {
            # Format array parameters like "val1", "val2"
            $formattedValue = '"' + ($paramValue -join '", "') + '"'
        } elseif ($paramValue -is [string] -and $paramValue.Contains(" ")) {
            # Quote strings with spaces
            $formattedValue = """$paramValue"""
        } else {
            # Simple strings, numbers, booleans
            $formattedValue = $paramValue.ToString()
        }
        $commandString += " -$paramName $formattedValue"
    }
    Write-Log "Script started with command: $commandString" "INFO" "Magenta"
}
catch {
    Write-Log "Could not log the command line. Error: $_" "WARNING" "Yellow"
}

# === Initialization and Connection ===
function Initialize-EntraPrerequisites {
    $requiredPSVersion = [Version]"5.1"
    $requiredModules = @(
        "Microsoft.Graph.Users",
        "Microsoft.Graph.Applications",
        "Microsoft.Graph.Identity.DirectoryManagement"
    )

    if ($PSVersionTable.PSVersion -lt $requiredPSVersion) {
        Write-Log "PowerShell $requiredPSVersion or higher is required. Current version: $($PSVersionTable.PSVersion)" "ERROR" "Red"
        exit 1
    }

    foreach ($module in $requiredModules) {
        try {
            if (-not (Get-Module -ListAvailable -Name $module)) {
                Write-Log "Module '$module' not found. Installing it..." "WARNING" "Yellow"
                Install-Module $module -Scope CurrentUser -Force
            }
            if (-not (Get-Module -Name $module)) {
                Import-Module $module -ErrorAction Stop
            }
            Write-Log "Successfully loaded module '$module'." "INFO"
        } catch {
            Write-Log "Failed to load module '$module'. $_" "ERROR" "Red"
            exit 1
        }
    }

    # Culture preservation
    $script:OriginalCulture = [System.Globalization.CultureInfo]::CurrentCulture
    $script:OriginalUICulture = [System.Globalization.CultureInfo]::CurrentUICulture

    [System.Threading.Thread]::CurrentThread.CurrentCulture = 'en-US'
    [System.Threading.Thread]::CurrentThread.CurrentUICulture = 'en-US'

    Write-Log "Entra ID prerequisites validated. Modules are ready." "INFO" "Green"
}

function Connect-EntraGraph {
    try {
        if (-not (Get-MgContext)) {
            Write-Log "Connecting to Microsoft Graph..." "INFO" "Green"
            Connect-MgGraph -Scopes "User.Read.All", "Directory.Read.All", "Application.Read.All", "AuditLog.Read.All"
        }

        if (-not (Get-MgContext)) {
            Write-Log "Login cancelled or authentication failed. Graph session not established." "ERROR" "Red"
            exit 1
        }
        Write-Log "Connected to Microsoft Graph successfully." "INFO" "Green"
    } catch {
        Write-Log "An error occurred while connecting to Microsoft Graph. $_" "ERROR" "Red"
        exit 1
    }
}

# Run Initialization and Connection
Initialize-EntraPrerequisites
Connect-EntraGraph

# === Data Retrieval ===
Write-Log "Fetching all users, applications, and service principals from the tenant..." "INFO"

$allUsers = Get-MgUser -All `
    -Property UserPrincipalName, AccountEnabled, SignInActivity, OnPremisesSyncEnabled, OnPremisesDomainName, Id
$applications = Get-MgApplication -All | Select-Object DisplayName, AppId
$servicePrincipals = Get-MgServicePrincipal -All | Select-Object DisplayName, AppId, AccountEnabled
$managedIdentities = Get-MgServicePrincipal -All -Filter "servicePrincipalType eq 'ManagedIdentity'"

Write-Log "Data retrieval complete. Processing data..." "INFO"

# === Data Processing Logic ===
$userReports = @()
$summary = [ordered]@{}
$cutoff = (Get-Date).AddDays(-$DaysInactive)

# Log the cutoff date
Write-Log "Inactive user cutoff date set to: $($cutoff.ToString("yyyy-MM-dd HH:mm:ss"))" "INFO"

foreach ($user in $allUsers) {
    $domain = ($user.UserPrincipalName -split "@")[1]

    # Initialize or get the domain's summary object
    if (-not ($summary.Keys -contains $domain)) {
        $domainSummary = [PSCustomObject]@{
            Domain                 = $domain
            TotalUsers             = 0
            ActiveUsers            = 0
            InactiveUsers          = 0
            NeverLoggedInUsers     = 0
            PatternMatchedUsers    = 0
        }
        $summary[$domain] = $domainSummary
    } else {
        $domainSummary = $summary[$domain]
    }
    
    # Increment counters for the current domain
    $domainSummary.TotalUsers++

    # Determine user activity status and increment counters
    $isActive = $false
    $isInactive = $false
    $isNeverLoggedIn = $false
    if ($user.SignInActivity.LastSignInDateTime) {
        if ($user.SignInActivity.LastSignInDateTime -ge $cutoff) {
            $domainSummary.ActiveUsers++
            $isActive = $true
        } else {
            $domainSummary.InactiveUsers++
            $isInactive = $true
        }
    } else {
        $domainSummary.NeverLoggedInUsers++
        $isNeverLoggedIn = $true
    }

    # Check for service account patterns and increment counter
    $isPatternMatched = $false
    foreach ($pattern in $UserServiceAccountNamesLike) {
        if ($user.UserPrincipalName -like "*$pattern*") {
            $isPatternMatched = $true
            break # Exit the loop once a match is found
        }
    }
    if ($isPatternMatched) {
        $domainSummary.PatternMatchedUsers++
    }

    # Store detailed user report for 'ByUser' mode
    $userReportEntry = [PSCustomObject]@{
    Directory            = $domain
    User                 = ($user.UserPrincipalName -split '@')[0]
    LastSignInDate       = $user.SignInActivity.LastSignInDateTime
    AccountEnabled       = $user.AccountEnabled
    ActiveUser           = [int]$isActive
    InactiveUser         = [int]$isInactive
    NeverLoggedInUser    = [int]$isNeverLoggedIn
    PatternMatchedUser   = [int][bool]$isPatternMatched
    SyncFromAD           = [bool]$user.OnPremisesSyncEnabled
    ADSourceDomain       = if ($user.OnPremisesSyncEnabled) { $user.OnPremisesDomainName } else { "N/A" }
    OwnedApps            = 0
    OwnedServicePrincipals = 0
    OwnedManagedIdentities = 0
    }    
    $userReports += $userReportEntry
}

$globalSummary = [PSCustomObject]@{
    Applications          = $applications.Count
    EnterpriseApps        = $servicePrincipals.Count
    ManagedIdentities     = $managedIdentities.Count
}

# === Report Generation Functions ===
function Get-ReportHeaders {
    param (
        [ValidateSet("ByUser", "ByDomain")]
        [string]$ReportType
    )

    switch ($ReportType) {
        "ByUser" {
            return @(
                @{Name='Directory'; Expression={ $_.Directory }},
                @{Name='User'; Expression={ $_.User }},
                @{Name='Account Enabled'; Expression={ $_.AccountEnabled }},
                @{Name='Active Users'; Expression={ $_.ActiveUser }},
                @{Name='Inactive Users'; Expression={ $_.InactiveUser }},
                @{Name='Never Logged In'; Expression={ $_.NeverLoggedInUser }},
                @{Name='Service Account Pattern'; Expression={ $_.PatternMatchedUsers }},
                @{Name='Synch from AD'; Expression={ $_.SyncFromAD }},
                @{Name='Source AD'; Expression={ $_.ADSourceDomain }},
                @{Name='App owned by User'; Expression={ $_.OwnedApps }},
                @{Name='SP owned by User'; Expression={ $_.OwnedServicePrincipals }},
                @{Name='Managed Identity'; Expression={ $_.OwnedManagedIdentities }}
            )
        }
        "ByDomain" {
            return @(
                @{Name='Directory'; Expression={ $_.Domain }},
                @{Name='Users'; Expression={ $_.TotalUsers }},
                @{Name='Active Users'; Expression={ $_.ActiveUsers }},
                @{Name='Inactive Users'; Expression={ $_.InactiveUsers }},
                @{Name='Never Logged In'; Expression={ $_.NeverLoggedInUsers }},
                @{Name='Service Account Pattern'; Expression={ $_.PatternMatchedUsers }},
                @{Name='Apps'; Expression={ $_.Applications }},
                @{Name='SP'; Expression={ $_.EnterpriseApps }},
                @{Name='Managed Identity'; Expression={ $_.ManagedIdentities }}
            )
        }
    }
}

function Export-CustomFormattedUserReport {
    param (
        [Parameter(Mandatory = $true)] [string]$OutputPath,
        [Parameter(Mandatory = $true)] [string]$Timestamp,
        [Parameter(Mandatory = $true)] [object[]]$UserReports,
        [Parameter(Mandatory = $true)] [object[]]$Headers
    )

    $fileName = "Entra_Audit_CustomUserReport_$Timestamp.html"
    $fullExportPath = Join-Path -Path $OutputPath -ChildPath $fileName

    $htmlBody = @"
<style>
    table { width: 100%; border-collapse: collapse; }
    th, td { border: 1px solid #ccc; padding: 8px; text-align: left; }
    th { background-color: #3498db; color: white; }
    tr:nth-child(even) { background-color: #f2f2f2; }
</style>
<h2>Détail utilisateur enrichi</h2>
<table>
    <tr>
"@

    foreach ($header in $Headers) {
        $htmlBody += "<th>$($header.Name)</th>"
    }
    $htmlBody += "</tr>"

    foreach ($report in $UserReports) {
        $htmlBody += "<tr>"
        foreach ($col in $Headers) {
            try {
                $value = if ($col.Expression -is [ScriptBlock]) {
                    & $col.Expression.Invoke($report)
                } elseif ($col.Expression -is [string]) {
                    $report.$($col.Expression)
                } else {
                    $col.Expression
                }
            } catch {
                Write-Warning "Erreur lors de l’évaluation de $($col.Name): $_"
                $value = "[Erreur]"
            }

            $htmlBody += "<td>$value</td>"
        }
        $htmlBody += "</tr>"
    }

    $htmlBody += "</table>"
    $htmlBody | Out-File -FilePath $fullExportPath -Encoding UTF8

    Write-Host "✔ Rapport HTML utilisateur exporté vers: $fullExportPath" -ForegroundColor Green
}

# Export the custom formatted report
function Export-CustomFormattedDomainReport {
    param (
        [Parameter(Mandatory = $true)] [string]$OutputPath,
        [Parameter(Mandatory = $true)] [string]$Timestamp,
        [Parameter(Mandatory = $true)] [object[]]$DomainReports,
        [Parameter(Mandatory = $true)] [object[]]$Headers
    )

    $fileName = "Entra_Audit_CustomDomainReport_$Timestamp.html"
    $fullExportPath = Join-Path -Path $OutputPath -ChildPath $fileName

    $htmlBody = @"
<style>
    table { width: 100%; border-collapse: collapse; }
    th, td { border: 1px solid #ccc; padding: 8px; text-align: left; }
    th { background-color: #2c3e50; color: white; }
    tr:nth-child(even) { background-color: #f9f9f9; }
</style>
<h2>Résumé par domaine enrichi</h2>
<table>
    <tr>
"@

    foreach ($header in $Headers) {
        $htmlBody += "<th>$($header.Name)</th>"
    }
    $htmlBody += "</tr>"

    foreach ($report in $DomainReports) {
        $htmlBody += "<tr>"
        foreach ($col in $Headers) {
            try {
                $value = if ($col.Expression -is [ScriptBlock]) {
                    & $col.Expression.Invoke($report)
                } elseif ($col.Expression -is [string]) {
                    $report.$($col.Expression)
                } else {
                    $col.Expression
                }
            } catch {
                Write-Warning "Erreur lors de l’évaluation de $($col.Name): $_"
                $value = "[Erreur]"
            }

            $htmlBody += "<td>$value</td>"
        }
        $htmlBody += "</tr>"
    }

    $htmlBody += "</table>"
    $htmlBody | Out-File -FilePath $fullExportPath -Encoding UTF8

    Write-Host "✔ Rapport HTML domaine exporté vers: $fullExportPath" -ForegroundColor Green
}

function Export-CustomFormattedFullReport {
    param (
        [string]$OutputPath,
        [string]$Timestamp,
        $Summary,
        [PSCustomObject]$GlobalSummary,
        [PSObject[]]$UserReports
    )

    Export-CustomFormattedDomainReport -OutputPath $outputPath -Timestamp $timestamp -DomainSummaries $summary -GlobalSummary $globalSummary -Headers $domainHeaders
    Export-CustomFormattedUserReport -OutputPath $outputPath -Timestamp $timestamp -UserReports $userReports -Headers $reportHeaders
}

# === Main Script Logic ===
Write-Log "Starting report generation..." "INFO" "Green"

$reportHeaders  = Get-ReportHeaders -ReportType "ByUser"
$domainHeaders  = Get-ReportHeaders -ReportType "ByDomain"

# === Header definitions ===
$HeadersByUser = @(
    @{ Name = "Directory";               Expression = "Directory" }
    @{ Name = "User";                    Expression = "User" }
    @{ Name = "Account Enabled";         Expression = "AccountEnabled" }
    @{ Name = "Active Users";            Expression = "ActiveUser" }
    @{ Name = "Inactive Users";          Expression = "InactiveUser" }
    @{ Name = "Never Logged In";         Expression = "NeverLoggedInUser" }
    @{ Name = "Service Account Pattern"; Expression = "PatternMatchedUser" }
    @{ Name = "Synch from AD";           Expression = "SyncFromAD" }
    @{ Name = "Source AD";               Expression = "ADSourceDomain" }
    @{ Name = "App owned by User";       Expression = "OwnedApps" }
    @{ Name = "SP owned by User";        Expression = "OwnedServicePrincipals" }
    @{ Name = "Managed Identity";        Expression = "OwnedManagedIdentities" }
)

$HeadersByDomain = @(
    @{ Name = "Domain";              Expression = "Domain" }
    @{ Name = "Total Users";         Expression = "TotalUsers" }
    @{ Name = "Active Users";        Expression = "ActiveUsers" }
    @{ Name = "Inactive Users";      Expression = "InactiveUsers" }
    @{ Name = "Never Logged In";     Expression = "NeverLoggedInUsers" }
    @{ Name = "Pattern Matched";     Expression = "PatternMatchedUsers" }
    @{ Name = "Applications";        Expression = "Applications" }
    @{ Name = "Enterprise Apps";     Expression = "EnterpriseApps" }
    @{ Name = "Managed Identities";  Expression = "ManagedIdentities" }
)

switch ($Mode) {
    "ByUser" {
        Export-CustomFormattedUserReport -OutputPath $outputPath -Timestamp $timestamp -UserReports $userReports -Headers $HeadersByUser
    }
    "ByDomain" {
        Export-CustomFormattedDomainReport -OutputPath $outputPath -Timestamp $timestamp -DomainReports $domainReport -Headers $HeadersByDomain
    }
    "Full" {
        Export-CustomFormattedFullReport -OutputPath $outputPath -Timestamp $timestamp -Summary $summary -GlobalSummary $globalSummary -UserReports $userReports
    }
}

# Reset Culture settings back to original value
[System.Threading.Thread]::CurrentThread.CurrentCulture = $OriginalCulture
[System.Threading.Thread]::CurrentThread.CurrentUICulture = $OriginalUICulture

Write-Log "Script execution complete." "INFO" "Green"