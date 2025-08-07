<#
.SYNOPSIS
  Full (“ByUser”) and Summary (“ByDomain”) Entra ID report.

.DESCRIPTION
  ByUser: every single user  
  ByDomain: aggregates counts from the ByUser data  

.PARAMETER Mode
  Full or Summary.

.PARAMETER DaysInactive
  Threshold in days to consider a user “inactive” (default 180).

.PARAMETER UserServiceAccountLike
  Wildcard pattern to identify service‐accounts (default “svc-*”).
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
            $baseHeaders = [PSCustomObject]@{
                Directory         = 'Directory'
                User              = 'User'
                AccountEnabled    = 'AccountEnabled'
                ActiveUser        = 'ActiveUser'
                InactiveUser      = 'InactiveUser'
                NeverLoggedInUser = 'NeverLoggedInUser'
                PatternMatchedUser = 'PatternMatchedUser'
                SyncFromAD        = 'SyncFromAD'
                ADSourceDomain    = 'ADSourceDomain'
            }

            if ($CheckOwnership) {
                $baseHeaders | Add-Member -MemberType NoteProperty -Name 'OwnedAppsCount' -Value 'AppRegistrationsOwned'
                $baseHeaders | Add-Member -MemberType NoteProperty -Name 'EnterpriseAppsCount' -Value 'EnterpriseAppsOwned'
                $baseHeaders | Add-Member -MemberType NoteProperty -Name 'ManagedIdentitiesCount' -Value 'ManagedIdentitiesOwned'
            }
            return $baseHeaders
        }
        
        'ByDomain' {
            return [PSCustomObject]@{
                Domain                        = 'Domain'
                TotalUsers                    = 'TotalUsers'
                AccountEnabledCount           = 'AccountEnabledCount'
                ActiveUsers                   = 'ActiveUsers'
                InactiveUsers                 = 'InactiveUsers'
                NeverLoggedInUsers            = 'NeverLoggedInUsers'
                PatternMatchedUsers           = 'PatternMatchedUsers'
                SyncFromADCount               = 'SyncFromADCount'
                ADSourceDomainCounts          = 'ADSourceDomainCounts'
                DomainApplicationsCount       = 'DomainApplicationsCount'
                DomainServicePrincipalCount   = 'DomainServicePrincipalCount'
                DomainManagedIdentitiesCount  = 'DomainManagedIdentitiesCount'
                ValidEnterpriseAppsCount      = 'ValidEnterpriseAppsCount'
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
                }
            }
        }
        else {
            Write-Verbose "Skipping detailed ownership checks for applications, service principals, and managed identities."
        }
        
        $output = foreach ($u in $users) {
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

            [PSCustomObject]@{
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

        Write-Verbose "Built $($output.Count) user records."
        return $output
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
    $now  = Get-Date

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
            # Corrected check: ensure AppId exists before lookup
            -not [string]::IsNullOrEmpty($_.AppId) -and ($AppDomainMap[$_.AppId] -eq $domain) -and ($_.ServicePrincipalType -eq 'Application')
          }).Count

        $tenantMIsCount = ($ManagedIdentities |
          Where-Object {
            # Corrected check: ensure AppId exists before lookup
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
    $fullPath = Join-Path -Path $OutputPath -ChildPath $FileName

    # Add a check to create the output directory if it doesn't exist
    if (-not (Test-Path -Path $OutputPath)) {
        New-Item -Path $OutputPath -ItemType Directory -Force
    }

    # Get the property names (the keys of the PSCustomObject)
    $propertyNames = $Columns.PSObject.Properties.Name

    # Select the properties and export to a CSV
    $data | Select-Object -Property $propertyNames | Export-Csv -Path $fullPath -NoTypeInformation -Force
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
        [PSCustomObject] $Columns
    )
    
        # Construct the full path
    $fullPath = Join-Path -Path $OutputPath -ChildPath $FileName

    # Add a check to create the output directory if it doesn't exist
    if (-not (Test-Path -Path $OutputPath)) {
        New-Item -Path $OutputPath -ItemType Directory -Force
    }

    # Get the property names from the PSCustomObject
    $propertyNames = $Columns.PSObject.Properties.Name

    $html = @()
    $html += '<html><head><style>body { font-family: sans-serif; }</style></head><body>'
    $html += "<h1>$Title</h1>"
    $html += '<hr>'
    $html += (ConvertTo-Html -Fragment -InputObject $Data -Property $propertyNames)
    $html += '</body></html>'

    $html | Out-File -FilePath $fullPath -Encoding UTF8 -Force
}

#==================================================================================================
# 5. MAIN
#==================================================================================================

#— 1) Récupérations globales Microsoft Graph
Write-Host "Loading global Graph data…" -ForegroundColor Cyan
# Get applications and create a lookup table for AppId -> PublisherDomain
$applications = Get-MgApplication -All -Property PublisherDomain,AppId,DisplayName
$appDomainMap = @{}
foreach ($app in $applications) {
    if (-not [string]::IsNullOrEmpty($app.PublisherDomain)) {
        $appDomainMap[$app.AppId] = $app.PublisherDomain
    }
}

# Get service principals with necessary properties
$servicePrincipals = Get-MgServicePrincipal -All -Property PublisherDomain,ServicePrincipalType,AppId,accountEnabled,passwordCredentials,keyCredentials
$managedIdentities = $servicePrincipals | Where-Object servicePrincipalType -eq 'ManagedIdentity'

#— 2) Construction du rapport détaillé par utilisateur
Write-Host "Building per-user dataset…" -ForegroundColor Cyan
$byUser = Get-ByUserData `
    -DaysInactive $DaysInactive `
    -ServicePattern $UserServiceAccountLike `
    -CheckOwnership:$CheckOwnership

#— 3) Agrégation par domaine
Write-Host "Aggregating by domain…" -ForegroundColor Cyan
$byDomain = Get-ByDomainData `
  -UserData          $byUser `
  -Applications      $applications `
  -ServicePrincipals $servicePrincipals `
  -ManagedIdentities $managedIdentities `
  -AppDomainMap      $appDomainMap

#— 4) Préparation des en-têtes de rapport
$userCols   = Get-ReportHeaders -Type ByUser -CheckOwnership:$CheckOwnership
$domainCols = Get-ReportHeaders -Type ByDomain

#— 5) Horodatage pour nommage des fichiers
$timestamp = Get-Date -Format 'yyyy-MM-dd_HH-mm'

#— 6) Export CSV & HTML en fonction du mode
if ($Mode -eq 'Full') {
    Write-Host "Exporting full reports…" -ForegroundColor Green

    Export-CsvReport -FileName "Full_ByUser_$timestamp.csv"    -Data  $byUser   -Columns $userCols
    Export-CsvReport -FileName "Full_ByDomain_$timestamp.csv"  -Data  $byDomain -Columns $domainCols
    Export-HtmlReport -FileName "Full_Report_$timestamp.html"   -Title 'Full EntraID Report' -Data  $byUser   -Columns $userCols
}
else {
    Write-Host "Exporting summary reports…" -ForegroundColor Green

    Export-CsvReport   -FileName "Summary_ByDomain_$timestamp.csv" -Data  $byDomain -Columns $domainCols
    Export-HtmlReport  -FileName "Summary_Report_$timestamp.html"  -Title 'EntraID Summary'    `
                       -Data  $byDomain -Columns $domainCols
}

Write-Host "All done!" -ForegroundColor Green
