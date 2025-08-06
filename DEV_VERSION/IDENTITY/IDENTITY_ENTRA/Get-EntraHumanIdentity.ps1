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
- 'ByDomain': A CSV report grouped by user domain suffix (e.g., @contoso.com).
- 'ByUser': A detailed CSV report for each user, including ownership details.
- 'Summary': A single-line CSV report with tenant-wide totals for key metrics.
- 'Html': A single, comprehensive HTML file with all report information (Summary, ByDomain, ByUser).
- 'Full': Generates all four report formats (Summary, ByDomain, ByUser, and Html) as separate files.

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
    [ValidateSet("ByDomain", "ByUser", "Summary", "Full", "Html")]
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

function Export-ByDomainReport {
    param (
        [string]$OutputPath,
        [string]$Timestamp,
        $Summary, # Removed [ordered]
        [PSCustomObject]$GlobalSummary
    )
    Write-Log "Generating 'ByDomain' report..." "INFO" "Cyan"
    
    $fileName = "Entra_Audit_ByDomain_$timestamp.csv"
    $fullExportPath = Join-Path -Path $OutputPath -ChildPath $fileName
    
    $domainReport = @()
    foreach ($key in $Summary.Keys) {
        $domainReport += $Summary[$key]
    }
    
    if ($domainReport.Count -gt 0) {
        $domainReport[0] | Add-Member -MemberType NoteProperty -Name 'Applications' -Value $GlobalSummary.Applications
        $domainReport[0] | Add-Member -MemberType NoteProperty -Name 'EnterpriseApps' -Value $GlobalSummary.EnterpriseApps
        $domainReport[0] | Add-Member -MemberType NoteProperty -Name 'ManagedIdentities' -Value $GlobalSummary.ManagedIdentities
    }

    $domainReport | Export-Csv -Path $fullExportPath -NoTypeInformation -Encoding UTF8
    Write-Log "ByDomain report saved to: $fullExportPath" "INFO" "Green"
}

function Export-ByUserReport {
    param (
        [string]$OutputPath,
        [string]$Timestamp,
        [PSObject[]]$AllUsers,
        [PSObject[]]$UserReports
    )
    Write-Log "Generating 'ByUser' report..." "INFO" "Cyan"
    
    $fileName = "Entra_Audit_ByUser_$timestamp.csv"
    $fullExportPath = Join-Path -Path $OutputPath -ChildPath $fileName

    # This loop is placed here because ownership data is only needed for the ByUser report
    foreach ($user in $AllUsers) {
        $userReportEntry = $UserReports | Where-Object { $_.User -eq ($user.UserPrincipalName -split '@')[0] }
        
        if ($userReportEntry) {
            $ownedObjects = Get-MgUserOwnedObject -UserId $user.Id -All
            
            $userReportEntry.OwnedApps = ($ownedObjects | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.application' }).Count
            $userReportEntry.OwnedServicePrincipals = ($ownedObjects | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.servicePrincipal' }).Count
            $userReportEntry.OwnedManagedIdentities = ($ownedObjects | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.servicePrincipal' -and $_.ServicePrincipalType -eq 'ManagedIdentity' }).Count
        }
    }

    $UserReports | Select-Object Directory, User, AccountEnabled, ActiveUser, InactiveUser, NeverLoggedInUser, PatternMatchedUser, SyncFromAD, ADSourceDomain, OwnedApps, OwnedServicePrincipals, OwnedManagedIdentities | Export-Csv -Path $fullExportPath -NoTypeInformation -Encoding UTF8
    Write-Log "ByUser report saved to: $fullExportPath" "INFO" "Green"
}

function Export-SummaryReport {
    param (
        [string]$OutputPath,
        [string]$Timestamp,
        $Summary, # Removed [ordered]
        [PSCustomObject]$GlobalSummary
    )
    Write-Log "Generating 'Summary' report..." "INFO" "Cyan"
    
    $fileName = "Entra_Audit_Summary_$timestamp.csv"
    $fullExportPath = Join-Path -Path $OutputPath -ChildPath $fileName

    $totalUsers = 0
    $activeUsers = 0
    $inactiveUsers = 0
    $neverLoggedInUsers = 0
    $patternMatchedUsers = 0

    foreach ($domainSummary in $Summary.Values) {
        $totalUsers += $domainSummary.TotalUsers
        $activeUsers += $domainSummary.ActiveUsers
        $inactiveUsers += $domainSummary.InactiveUsers
        $neverLoggedInUsers += $domainSummary.NeverLoggedInUsers
        $patternMatchedUsers += $domainSummary.PatternMatchedUsers
    }

    $total = [PSCustomObject]@{
        TotalUsers            = $totalUsers
        ActiveUsers           = $activeUsers
        InactiveUsers         = $inactiveUsers
        NeverLoggedInUsers    = $neverLoggedInUsers
        PatternMatchedUsers   = $patternMatchedUsers
        Applications          = $GlobalSummary.Applications
        EnterpriseApps        = $GlobalSummary.EnterpriseApps
        ManagedIdentities     = $GlobalSummary.ManagedIdentities
    }
    
    $total | Export-Csv -Path $fullExportPath -NoTypeInformation -Encoding UTF8
    Write-Log "Summary report saved to: $fullExportPath" "INFO" "Green"
}

function Export-HtmlReport {
    param (
        [string]$OutputPath,
        [string]$Timestamp,
        $Summary,
        [PSCustomObject]$GlobalSummary,
        [PSObject[]]$AllUsers,
        [PSObject[]]$UserReports
    )
    Write-Log "Generating 'HTML' report..." "INFO" "Cyan"

    $fileName = "Entra_Audit_Report_$timestamp.html"
    $fullExportPath = Join-Path -Path $OutputPath -ChildPath $fileName

    # 1. Create the Summary table data
    $total = [PSCustomObject]@{
        TotalUsers            = ($Summary.Values | Measure-Object TotalUsers -Sum).Sum
        ActiveUsers           = ($Summary.Values | Measure-Object ActiveUsers -Sum).Sum
        InactiveUsers         = ($Summary.Values | Measure-Object InactiveUsers -Sum).Sum
        NeverLoggedInUsers    = ($Summary.Values | Measure-Object NeverLoggedInUsers -Sum).Sum
        PatternMatchedUsers   = ($Summary.Values | Measure-Object PatternMatchedUsers -Sum).Sum
        Applications          = $GlobalSummary.Applications
        EnterpriseApps        = $GlobalSummary.EnterpriseApps
        ManagedIdentities     = $GlobalSummary.ManagedIdentities
    }
    $summaryHtml = $total | ConvertTo-Html -Fragment -Property TotalUsers, ActiveUsers, InactiveUsers, NeverLoggedInUsers, PatternMatchedUsers, Applications, EnterpriseApps, ManagedIdentities

    # 2. Create the ByDomain table data
    $domainReport = @()
    foreach ($key in $Summary.Keys) {
        $domainReport += $Summary[$key]
    }
    $domainHtml = $domainReport | Sort-Object Domain | ConvertTo-Html -Fragment

    # 3. Create the ByUser table data
    # This loop is placed here because ownership data is only needed for the HTML/ByUser reports
    foreach ($user in $AllUsers) {
        $userReportEntry = $UserReports | Where-Object { $_.User -eq ($user.UserPrincipalName -split '@')[0] }
        
        if ($userReportEntry) {
            $ownedObjects = Get-MgUserOwnedObject -UserId $user.Id -All
            
            $userReportEntry.OwnedApps = ($ownedObjects | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.application' }).Count
            $userReportEntry.OwnedServicePrincipals = ($ownedObjects | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.servicePrincipal' }).Count
            $userReportEntry.OwnedManagedIdentities = ($ownedObjects | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.servicePrincipal' -and $_.ServicePrincipalType -eq 'ManagedIdentity' }).Count
        }
    }
    # Select a subset of columns for the HTML table and exclude LastSignInDate
    $userReportHtml = $UserReports | Select-Object Directory, User, AccountEnabled, ActiveUser, InactiveUser, NeverLoggedInUser, SyncFromAD, ADSourceDomain, OwnedApps, OwnedServicePrincipals, OwnedManagedIdentities | ConvertTo-Html -Fragment
    
    # 4. Assemble the final HTML file
    $htmlBody = @"
    <style>
    body { font-family: Arial, sans-serif; margin: 20px; background-color: #f4f4f9; color: #333; }
    h1, h2 { color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 5px; }
    table { width: 100%; border-collapse: collapse; margin-bottom: 20px; box-shadow: 0 2px 3px rgba(0,0,0,0.1); }
    th, td { text-align: left; padding: 12px; border: 1px solid #ddd; }
    th { background-color: #3498db; color: white; font-weight: bold; }
    tr:nth-child(even) { background-color: #f2f2f2; }
    tr:hover { background-color: #e9e9e9; }
    .note { font-style: italic; color: #7f8c8d; margin-top: 20px; }
    </style>

    <h1>Microsoft Entra ID Audit Report for RUBRIK Engineer</h1>
    <p>Report generated on: $(Get-Date)</p>

    <h2>Tenant-wide Summary</h2>
    $summaryHtml

    <h2>Users by Domain</h2>
    $domainHtml
    
    <h2>User Ownership and Activity Details</h2>
    $userReportHtml

    <p class="note">Note: This is a snapshot of the Entra ID tenant at the time of report generation.</p>
"@
    
    $htmlBody | Out-File -FilePath $fullExportPath -Encoding UTF8
    Write-Log "HTML report saved to: $fullExportPath" "INFO" "Green"
}

# === Main Script Logic ===
Write-Log "Starting report generation..." "INFO" "Green"

switch ($Mode) {
    "ByDomain" {
        Export-ByDomainReport -OutputPath $outputPath -Timestamp $timestamp -Summary $summary -GlobalSummary $globalSummary
    }
    "ByUser" {
        Export-ByUserReport -OutputPath $outputPath -Timestamp $timestamp -AllUsers $allUsers -UserReports $userReports
    }
    "Summary" {
        Export-SummaryReport -OutputPath $outputPath -Timestamp $timestamp -Summary $summary -GlobalSummary $globalSummary
    }
    "Html" {
        Export-HtmlReport -OutputPath $outputPath -Timestamp $timestamp -Summary $summary -GlobalSummary $globalSummary -AllUsers $allUsers -UserReports $userReports
    }
    "Full" {
        Write-Log "Generating 'Full' audit (Summary, ByDomain, ByUser, and HTML reports)..." "INFO" "Magenta"
        
        Export-SummaryReport -OutputPath $outputPath -Timestamp $timestamp -Summary $summary -GlobalSummary $globalSummary
        Export-ByDomainReport -OutputPath $outputPath -Timestamp $timestamp -Summary $summary -GlobalSummary $globalSummary
        Export-ByUserReport -OutputPath $outputPath -Timestamp $timestamp -AllUsers $allUsers -UserReports $userReports
        Export-HtmlReport -OutputPath $outputPath -Timestamp $timestamp -Summary $summary -GlobalSummary $globalSummary -AllUsers $allUsers -UserReports $userReports
    }
}

# Reset Culture settings back to original value
[System.Threading.Thread]::CurrentThread.CurrentCulture = $OriginalCulture
[System.Threading.Thread]::CurrentThread.CurrentUICulture = $OriginalUICulture

Write-Log "Script execution complete." "INFO" "Green"