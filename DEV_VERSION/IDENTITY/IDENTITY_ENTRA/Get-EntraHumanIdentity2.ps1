<#
Synopsis
The script is a PowerShell-based reporting tool for Entra ID (formerly Azure Active Directory). It connects to Microsoft Graph to retrieve detailed information on users, applications, and service principals, then generates comprehensive reports in both CSV and HTML formats. It supports two modes: a detailed "Full" report for all users and a "Summary" report aggregated by domain. The script is designed to be self-sufficient, checking for and installing necessary modules before execution.

Parameters
UserServiceAccountNamesLike: An array of strings used to identify service accounts by matching patterns in their User Principal Name (e.g., "svc-", "sa-"). This is optional.

Mode: Specifies the type of reports to generate. The valid options are "Full" (default) or "Summary".

DaysInactive: An integer representing the number of days of inactivity to check for when identifying inactive users. The default value is 180.

CheckOwnership: A switch parameter. When present, the script performs additional, more time-consuming calls to count the number of applications and service principals owned by each user. This is not used by default.

Example of Usage
Full Report with Ownership Check
The following command runs the script in Full mode, checks for users inactive for 180 days, identifies service accounts with names starting with "svc-" or "sa-", and performs the ownership check.

PowerShell

.\EntraID-ReportGenerator.ps1 -Mode Full -DaysInactive 180 -UserServiceAccountNamesLike "svc-", "sa-" -CheckOwnership
Summary Report
This command runs the script in Summary mode, which only generates the aggregated domain report.

PowerShell

.\EntraID-ReportGenerator.ps1 -Mode Summary
#>

param (
    [string[]]$UserServiceAccountNamesLike = @(),
    [ValidateSet("Summary", "Full")]
    [string]$Mode = "Full",
    [int]$DaysInactive = 180,
    [switch]$CheckOwnership
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
    Write-Log "Loading required modules..." "INFO" "Cyan"

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
            Write-Log "Successfully loaded module '$module'." "INFO" "Green"
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

    Write-Log "Successfully validated Entra ID prerequisites. Modules are ready." "INFO" "Green"
}

function Connect-EntraGraph {

    Write-Log "Connecting to Microsoft Graph" "INFO" "Cyan"

    try {
        if (-not (Get-MgContext)) {
            #Write-Log "Connecting to Microsoft Graph..." "INFO" "Green"
            Connect-MgGraph -Scopes "User.Read.All", "Directory.Read.All", "Application.Read.All", "AuditLog.Read.All"
        }

        if (-not (Get-MgContext)) {
            Write-Log "Login cancelled or authentication failed. Graph session not established." "ERROR" "Red"
            exit 1
        }
        Write-Log "Successfully connected to Microsoft Graph." "INFO" "Green"
    } catch {
        Write-Log "An error occurred while connecting to Microsoft Graph. $_" "ERROR" "Red"
        exit 1
    }
}

# Run Initialization and Connection
Initialize-EntraPrerequisites
Connect-EntraGraph

#————————————————————————————————————————
# 1. HEADERS
#————————————————————————————————————————
function Get-ReportHeaders {
    param(
        [Parameter(Mandatory)]
        [ValidateSet('ByUser', 'ByDomain')]
        [string] $Type,
        [Parameter()]
        [switch] $CheckOwnership
    )
    
    switch ($Type) {
        'ByUser' {
            $baseHeaders = [ordered]@{
                Directory               = 'Directory'
                User                    = 'User'
                AccountEnabled          = 'Account Enabled'
                ActiveUser              = 'Active Users'
                InactiveUser            = 'Inactive Users'
                NeverLoggedInUser       = 'Never Logged In'
                PatternMatchedUser      = 'Service Account Pattern'
                SyncFromAD              = 'Synch from AD'
                ADSourceDomain          = 'Source AD'
            }

            if ($CheckOwnership) {
                $baseHeaders['OwnedAppsCount']          = 'App owned by User'
                $baseHeaders['EnterpriseAppsCount']     = 'SP owned by User'
                $baseHeaders['ManagedIdentitiesCount']  = 'Managed Identity'
            }
            return [PSCustomObject]$baseHeaders
        }
        
        'ByDomain' {
            return [PSCustomObject]@{
                Domain                        = 'Directory'
                TotalUsers                    = 'Total Users'
                ActiveUsers                   = 'Active Users'
                InactiveUsers                 = 'Inactive Users'
                NeverLoggedInUsers            = 'Never Logged In Users'
                PatternMatchedUsers           = 'Service Account Pattern'
                DomainApplicationsCount       = 'Applications'
                DomainServicePrincipalCount   = 'Service Principals'
                DomainManagedIdentitiesCount  = 'Managed Identities'
            }
        }
    }
}

#-------------------------------------------------------------------
# 2. DETAIL: Build ByUser List (with Owned/Enterprise/MI counts)
#-------------------------------------------------------------------
function Get-ByUserData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [int]      $DaysInactive,

        [Parameter()]
        [string[]] $ServicePattern = @(),

        [Parameter()]
        [switch]   $CheckOwnership
    )

    begin {
        $cutoff = (Get-Date).AddDays(-$DaysInactive)
        Write-Verbose "Inactivity cutoff date: $cutoff"
        
        # Initialize an array to store the output, making it accessible to all blocks
        $script:output = @()
    }

    process {
        Write-Verbose "Retrieving users..."
        $users = Get-MgUser -All `
            -Property Id,UserPrincipalName,AccountEnabled,SignInActivity, `
                      OnPremisesSyncEnabled,OnPremisesDomainName `
            -ErrorAction Stop

        Write-Verbose "Retrieving applications..."
        $allApps = Get-MgApplication -All -ErrorAction Stop

        Write-Verbose "Retrieving service principals..."
        $filterSP = "servicePrincipalType eq 'Application' or servicePrincipalType eq 'ManagedIdentity'"
        $allSPs = Get-MgServicePrincipal -All -Filter $filterSP -ErrorAction Stop

        $appOwners   = @{}
        $spAppOwners = @{}
        $spMiOwners  = @{}

        if ($CheckOwnership) {
            Write-Verbose "Retrieving ownership for each application (this may take a while)..."
            foreach ($app in $allApps) {
                try {
                    $owners = Get-MgApplicationOwner -ApplicationId $app.Id
                    foreach ($owner in $owners) {
                        $appOwners[$owner.Id] = ($appOwners[$owner.Id] + 1)
                    }
                }
                catch {
                    Write-Verbose "Could not get owners for application $($app.DisplayName). Error: $_"
                    Write-Log "Could not get owners for application $($app.DisplayName). Error: $_" "ERROR" "RED"
                }
            }

            Write-Verbose "Retrieving ownership for each service principal and managed identity (this may take a while)..."
            foreach ($sp in $allSPs) {
                try {
                    $owners = Get-MgServicePrincipalOwner -ServicePrincipalId $sp.Id
                    foreach ($owner in $owners) {
                        switch ($sp.ServicePrincipalType) {
                            'Application'     { $spAppOwners[$owner.Id] = ($spAppOwners[$owner.Id] + 1) }
                            'ManagedIdentity' { $spMiOwners[$owner.Id]  = ($spMiOwners[$owner.Id]  + 1) }
                        }
                    }
                }
                catch {
                    Write-Verbose "Could not get owners for service principal $($sp.DisplayName). Error: $_"
                    Write-Log "Could not get owners for service principal $($sp.DisplayName). Error: $_" "ERROR" "RED"
                }
            }
        }
        else {
            Write-Verbose "Skipping detailed ownership checks for applications, service principals, and managed identities."
        }
        
        foreach ($u in $users) {
            Write-Verbose "Processing user: $($u.UserPrincipalName)"

            $parts     = if ($u.UserPrincipalName) { $u.UserPrincipalName.Split('@') } else { @('','') }
            $user      = $parts[0]
            $directory = $parts[1]

            $lastSignIn = if ($u.SignInActivity?.LastSignInDateTime) {
                [datetime]$u.SignInActivity.LastSignInDateTime
            } else {
                $null
            }

            $isNeverLoggedIn = -not $lastSignIn
            $isActive        = $lastSignIn -and ($lastSignIn -ge $cutoff)
            $isInactive      = -not $isActive

            $patternMatched = $false
            foreach ($p in $ServicePattern) {
                if ($u.UserPrincipalName -like "*$p*") {
                    $patternMatched = $true
                    break
                }
            }

            $syncFromAD     = [bool]$u.OnPremisesSyncEnabled
            $adSourceDomain = if ($syncFromAD) { $u.OnPremisesDomainName } else { $false }

            $ownedCount      = $appOwners[$u.Id]      -or 0
            $enterpriseCount = $spAppOwners[$u.Id]    -or 0
            $miCount         = $spMiOwners[$u.Id]     -or 0

            $script:output += [PSCustomObject]@{
                Directory               = $directory
                User                    = $user
                AccountEnabled          = [int]$u.AccountEnabled
                ActiveUser              = [int]$isActive
                InactiveUser            = [int]$isInactive
                NeverLoggedInUser       = [int]$isNeverLoggedIn
                PatternMatchedUser      = [int]$patternMatched
                SyncFromAD              = [int]$syncFromAD
                ADSourceDomain          = $adSourceDomain
                OwnedAppsCount          = $ownedCount
                EnterpriseAppsCount     = $enterpriseCount
                ManagedIdentitiesCount  = $miCount
            }
        }
    }

    end {
        Write-Verbose "Built $($script:output.Count) user records. Calculating totals..."
        Write-Log "Successfully built $($script:output.Count) user records." "INFO" "Green"

        # Build a grand-total row
        $totals = [ordered]@{ Directory = "TOTAL"; User = "" }
        foreach ($col in $script:output | Get-Member -MemberType NoteProperty | Select-Object -Expand Name | Where-Object { $_ -ne 'Directory' -and $_ -ne 'User' -and $_ -ne 'ADSourceDomain' }) {
            $totals[$col] = ($script:output | Measure-Object -Property $col -Sum).Sum
        }
        $totals['ADSourceDomain'] = ''
        
        # Add the total row to the end of the data and return it
        $script:output += [PSCustomObject]$totals
        return $script:output
  }
}

#————————————————————————————————————————
# 3. SUMMARY: Group Into ByDomain
#————————————————————————————————————————
function Get-ByDomainData {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [object[]] $UserData,

    [Parameter(Mandatory)]
    [object[]] $Applications,

    [Parameter(Mandatory)]
    [object[]] $ServicePrincipals,

    [Parameter()]
    [object[]] $ManagedIdentities = @(),

    [Parameter(Mandatory)]
    [Hashtable] $AppDomainMap
  )

  begin {
    $rows = @()

    # Grab your tenant GUID and all verified domains
    $org = Get-MgOrganization -ErrorAction Stop
    $tenantId = $org.Id

    # Build a map: domainName -> tenantId
    $domainTenantMap = @{}
    $verifiedDomains = @()
    foreach ($vd in $org.VerifiedDomains) {
      $domainTenantMap[$vd.Name] = $tenantId
      $verifiedDomains += $vd.Name
    }
  }

  process {
    # Process for each identified domain
    $UserData |
      Group-Object -Property Directory |
      ForEach-Object {
        $domain = $_.Name
        $grpUsers = $_.Group

        $domainAppsCount = ($Applications | Where-Object { $_.publisherDomain -eq $domain }).Count

        $tenantAppsCount = ($ServicePrincipals |
          Where-Object {
            # Ensure AppId exists before lookup
            -not [string]::IsNullOrEmpty($_.AppId) -and ($AppDomainMap[$_.AppId] -eq $domain) -and ($_.ServicePrincipalType -eq 'Application')
          }).Count

        $tenantMIsCount = ($ManagedIdentities |
          Where-Object {
            # Ensure AppId exists before lookup
            -not [string]::IsNullOrEmpty($_.AppId) -and ($AppDomainMap[$_.AppId] -eq $domain)
          }).Count

        # ValidEnterpriseAppsCount is set to 0 to avoid slow API calls
        $validEA = 0

        $rows += [PSCustomObject]@{
          Domain = $domain
          TotalUsers = $grpUsers.Count
          AccountEnabledCount = ($grpUsers | Where-Object { $_.AccountEnabled -eq 1 }).Count
          ActiveUsers = ($grpUsers | Where-Object { $_.ActiveUser -eq 1 }).Count
          InactiveUsers = ($grpUsers | Where-Object { $_.InactiveUser -eq 1 }).Count
          NeverLoggedInUsers = ($grpUsers | Where-Object { $_.NeverLoggedInUser -eq 1 }).Count
          PatternMatchedUsers = ($grpUsers | Where-Object { $_.PatternMatchedUser -eq 1 }).Count
          SyncFromADCount = ($grpUsers | Where-Object { $_.SyncFromAD -eq 1 }).Count
          ADSourceDomainCounts = (
            $grpUsers |
            Where-Object { $_.SyncFromAD -eq 1 } |
            Group-Object -Property ADSourceDomain |
            ForEach-Object { "$($_.Name):$($_.Count)" }
          ) -join '; '
          DomainApplicationsCount = $domainAppsCount
          DomainServicePrincipalCount = $tenantAppsCount
          DomainManagedIdentitiesCount = $tenantMIsCount
          ValidEnterpriseAppsCount = $validEA
        }
      }

    # Handle the 'other' domains
    $otherApps = $Applications | Where-Object {
      -not ($verifiedDomains -contains $_.publisherDomain) -or [string]::IsNullOrEmpty($_.publisherDomain)
    }
    $otherSPs = $ServicePrincipals | Where-Object {
      # Corrected check: ensure AppId exists before lookup
      -not [string]::IsNullOrEmpty($_.AppId) -and (-not ($verifiedDomains -contains $AppDomainMap[$_.AppId]) -or [string]::IsNullOrEmpty($AppDomainMap[$_.AppId]))
    }
    $otherMIs = $ManagedIdentities | Where-Object {
      # Corrected check: ensure AppId exists before lookup
      -not [string]::IsNullOrEmpty($_.AppId) -and (-not ($verifiedDomains -contains $AppDomainMap[$_.AppId]) -or [string]::IsNullOrEmpty($AppDomainMap[$_.AppId]))
    }
    
    # ValidEnterpriseAppsCount is set to 0 to avoid slow API calls
    $validEA = 0

    $rows += [PSCustomObject]@{
      Domain = "Service principals from other domains"
      TotalUsers = 0
      AccountEnabledCount = 0
      ActiveUsers = 0
      InactiveUsers = 0
      NeverLoggedInUsers = 0
      PatternMatchedUsers = 0
      SyncFromADCount = 0
      ADSourceDomainCounts = ""
      DomainApplicationsCount = $otherApps.Count
      DomainServicePrincipalCount = ($otherSPs | Where-Object ServicePrincipalType -eq 'Application').Count
      DomainManagedIdentitiesCount = $otherMIs.Count
      ValidEnterpriseAppsCount = $validEA
    }
  }

  end {
    # Build a grand‐total row
    $totals = [ordered]@{ Domain = 'TOTAL' }
    foreach ($col in $rows | Get-Member -MemberType NoteProperty | Select-Object -Expand Name | Where-Object { $_ -ne 'Domain' -and $_ -ne 'ADSourceDomainCounts' }) {
      $totals[$col] = ($rows | Measure-Object -Property $col -Sum).Sum
    }
    # Add a blank value for ADSourceDomainCounts (since it can't be summed)
    $totals['ADSourceDomainCounts'] = ''
    
    Write-Log "Successfully aggregated $($rows.Count-1) different domain(s)." "INFO" "Green"
    return $rows + [PSCustomObject]$totals
  }
  
}

#————————————————————————————————————————
# 4. EXPORTERS (CSV + HTML)
#————————————————————————————————————————
function Export-CsvReport {
    param(
        [Parameter(Mandatory)]
        [string]   $FileName,

        [Parameter(Mandatory)]
        [object[]] $Data,

        [Parameter(Mandatory)]
        [PSCustomObject] $Columns
        
    )

    # Construct the full path
    $fullPath = Join-Path -Path $outputPath -ChildPath $FileName
    
    # Create a new, empty array for the calculated properties
    $calculatedProperties = @()

    try {

        # Iterate through the columns and build the array of calculated properties
         foreach ($name in $Columns.PSObject.Properties.Name) {
        $header = $Columns."$name" # Get the custom header text
        
        # Add a new calculated property to the array
        $calculatedProperties += @{
            Name       = $header
            Expression = [scriptblock]::Create("`$_.`"$name`"")
        }
    }
    
        # Select the properties and export to a CSV with custom headers
        $data | Select-Object -Property $calculatedProperties | Export-Csv -Path $fullPath -NoTypeInformation -Force
        
        Write-Log "Successfully exported all objects in CSV file $fullPath" "INFO" "Green"

    }
    catch {
        Write-Log "Could not export to CSV file $fullPath. Error: $_" "ERROR" "RED"
    }
}

function Export-HtmlReport {
    param(
        [Parameter(Mandatory)]
        [string]   $FileName,

        [Parameter(Mandatory)]
        [string]   $Title,

        [Parameter(Mandatory)]
        [object[]] $Data,

        [Parameter(Mandatory)]
        [PSCustomObject] $Columns,

        [Parameter()]
        [string] $SecondReportTitle,

        [Parameter()]
        [object[]] $SecondReportData,

        [Parameter()]
        [PSCustomObject] $SecondReportColumns,
        
        [Parameter(Mandatory)]
        [string] $OutputPath
    )

    # Construct the full path
    $fullPath = Join-Path -Path $outputPath -ChildPath $FileName

    try {
        # Internal function to build an HTML table from data and columns
        function New-HtmlTable {
            param(
                [Parameter(Mandatory)]
                [string] $TableTitle,

                [Parameter(Mandatory)]
                [object[]] $TableData,

                [Parameter(Mandatory)]
                [PSCustomObject] $TableColumns
            )
            
            $html = "<h2>$TableTitle</h2>"
            $html += '<table><tr>'

            # Add headers
            foreach ($header in $TableColumns.PSObject.Properties.Value) {
                $html += "<th>$header</th>"
            }
            $html += '</tr>'

            # Add data rows
            foreach ($row in $TableData) {
                $html += '<tr>'
                foreach ($colName in $TableColumns.PSObject.Properties.Name) {
                    $value = $row."$colName"
                    $html += "<td>$value</td>"
                }
                $html += '</tr>'
            }

            $html += '</table>'
            return $html
        }

        $htmlBody = @"
<html>
<head>
    <style>
        body { font-family: sans-serif; }
        table { width: 100%; border-collapse: collapse; margin-bottom: 20px; }
        th, td { border: 1px solid #ccc; padding: 8px; text-align: left; }
        th { background-color: #3498db; color: white; }
        tr:nth-child(even) { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <h1>ENTRA ID Report</h1>
    <hr>
"@

        # Add the first table
        $htmlBody += New-HtmlTable -TableTitle $Title -TableData $Data -TableColumns $Columns

        # If a second report is provided, add it
        if ($SecondReportData) {
            $htmlBody += "<br>"
            $htmlBody += New-HtmlTable -TableTitle $SecondReportTitle -TableData $SecondReportData -TableColumns $SecondReportColumns
        }
        
        $htmlBody += @"
</body>
</html>
"@
        
        $htmlBody | Out-File -FilePath $fullPath -Encoding UTF8
        Write-Log "Successfully exported HTML report to $fullPath" "INFO" "Green"
    }
    catch {
        Write-Log "Could not export to HTML file $fullPath. Error: $_" "ERROR" "RED"
    }
}

#==================================================================================================
# 5. MAIN
#==================================================================================================

#— 1) Récupérations globales Microsoft Graph
# Get applications and create a lookup table for AppId -> PublisherDomain
Write-Log "Loading global Graph data - Fetching Applications..." "INFO" "Cyan"
$applications = Get-MgApplication -All -Property PublisherDomain,AppId,DisplayName
$appDomainMap = @{}
foreach ($app in $applications) {
    if (-not [string]::IsNullOrEmpty($app.PublisherDomain)) {
        $appDomainMap[$app.AppId] = $app.PublisherDomain
    }
}

# Get service principals with necessary properties
Write-Log "Loading global Graph data - Fetching Service Principals..." "INFO" "Cyan"
$servicePrincipals = Get-MgServicePrincipal -All -Property PublisherDomain,ServicePrincipalType,AppId,accountEnabled,passwordCredentials,keyCredentials

Write-Log "Loading global Graph data - Fetching Managed Identities..." "INFO" "Cyan"
$managedIdentities = $servicePrincipals | Where-Object servicePrincipalType -eq 'ManagedIdentity'

#— 2) Construction du rapport détaillé par utilisateur
Write-Log "Building per-user dataset..." "INFO" "Cyan"
$byUser = Get-ByUserData `
    -DaysInactive $DaysInactive `
    -ServicePattern $UserServiceAccountNamesLike `
    -CheckOwnership:$CheckOwnership

# Filter out the last row (the 'TOTAL' row) before passing the data to Get-ByDomainData
$domainDataInput = $byUser | Select-Object -SkipLast 1

#— 3) Agrégation par domaine
Write-Log "Building aggregated report by Domain..." "INFO" "Cyan"
$byDomain = Get-ByDomainData `
  -UserData          $domainDataInput `
  -Applications      $applications `
  -ServicePrincipals $servicePrincipals `
  -ManagedIdentities $managedIdentities `
  -AppDomainMap      $appDomainMap

#— 4) Préparation des en-têtes de rapport
$userCols   = Get-ReportHeaders -Type ByUser -CheckOwnership:$CheckOwnership
$domainCols = Get-ReportHeaders -Type ByDomain

#— 6) Export CSV & HTML en fonction du mode
if ($Mode -eq 'Full') {
    Write-Log "Exporting Full reports in CSV and HTML format..." "INFO" "Cyan"

    Export-CsvReport -FileName "Full_ByUser_$timestamp.csv"    -Data  $byUser   -Columns $userCols
    Export-CsvReport -FileName "Full_ByDomain_$timestamp.csv"  -Data  $byDomain -Columns $domainCols
    #Export-HtmlReport -FileName "Full_Report_$timestamp.html"   -Title 'Full EntraID Report' -Data  $byUser   -Columns $userCols
    Export-HtmlReport -FileName "Full_Report_$timestamp.html" `
                   -Title 'User Details' `
                   -Data  $byUser `
                   -Columns $userCols `
                   -SecondReportTitle 'Domain Summary' `
                   -SecondReportData $byDomain `
                   -SecondReportColumns $domainCols `
                   -OutputPath $OutputPath
}

else {
    Write-Log "Exporting Summary reports in CSV and HTML format..." "INFO" "Cyan"

    Export-CsvReport   -FileName "Summary_ByDomain_$timestamp.csv" -Data  $byDomain -Columns $domainCols
    Export-HtmlReport  -FileName "Summary_Report_$timestamp.html"  -Title 'EntraID Summary'    `
                       -Data  $byDomain -Columns $domainCols                
}

# Reset Culture settings back to original value
[System.Threading.Thread]::CurrentThread.CurrentCulture = $OriginalCulture
[System.Threading.Thread]::CurrentThread.CurrentUICulture = $OriginalUICulture

Write-Log "ENTRA ID reports generation completed." "INFO" "Green"
