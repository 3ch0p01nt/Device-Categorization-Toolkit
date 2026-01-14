<#
.SYNOPSIS
    Export device categorization results to CSV.

.DESCRIPTION
    This script executes the device categorization KQL query against either
    Microsoft Defender XDR Advanced Hunting or Microsoft Sentinel, then
    exports the results to a timestamped CSV file.

.PARAMETER Target
    The platform to query: 'Defender' or 'Sentinel'

.PARAMETER TenantId
    Azure AD Tenant ID for authentication

.PARAMETER WorkspaceId
    (Sentinel only) Log Analytics Workspace ID

.PARAMETER OutputPath
    Path where the CSV will be saved. Defaults to ../output/

.PARAMETER LookbackDays
    Number of days to look back for device activity. Default is 30.

.EXAMPLE
    .\Export-DeviceCategories.ps1 -Target Defender -TenantId "your-tenant-id"

.EXAMPLE
    .\Export-DeviceCategories.ps1 -Target Sentinel -TenantId "your-tenant-id" -WorkspaceId "your-workspace-id"

.NOTES
    Prerequisites:
    - For Defender: Microsoft.Graph.Security module or direct API access
    - For Sentinel: Az.OperationalInsights module
    - Appropriate permissions (SecurityReader for Defender, Log Analytics Reader for Sentinel)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Defender', 'Sentinel')]
    [string]$Target,

    [Parameter(Mandatory = $true)]
    [string]$TenantId,

    [Parameter(Mandatory = $false)]
    [string]$WorkspaceId,

    [Parameter(Mandatory = $false)]
    [string]$OutputPath = (Join-Path $PSScriptRoot "..\output"),

    [Parameter(Mandatory = $false)]
    [int]$LookbackDays = 30
)

$ErrorActionPreference = "Stop"

# Determine script and query paths
$ScriptRoot = $PSScriptRoot
$QueriesPath = Join-Path $ScriptRoot "..\queries"

# Select appropriate query file based on target
if ($Target -eq 'Defender') {
    $QueryFile = Join-Path $QueriesPath "defender\99-combined-categorization.kql"
} else {
    $QueryFile = Join-Path $QueriesPath "sentinel\99-combined-categorization.kql"
}

# Validate query file exists
if (-not (Test-Path $QueryFile)) {
    Write-Error "Query file not found: $QueryFile"
    exit 1
}

# Read the query
$Query = Get-Content $QueryFile -Raw

# Update lookback days in the query
$Query = $Query -replace 'let LookbackDays = \d+;', "let LookbackDays = $LookbackDays;"

Write-Host "Device Categorization Export" -ForegroundColor Cyan
Write-Host "=============================" -ForegroundColor Cyan
Write-Host "Target: $Target" -ForegroundColor White
Write-Host "Tenant: $TenantId" -ForegroundColor White
Write-Host "Lookback: $LookbackDays days" -ForegroundColor White
Write-Host ""

# Ensure output directory exists
if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

# Generate output filename with timestamp
$Timestamp = Get-Date -Format "yyyy-MM-dd_HHmmss"
$OutputFile = Join-Path $OutputPath "DeviceCategories_${Target}_${Timestamp}.csv"

function Invoke-DefenderQuery {
    param([string]$Query, [string]$TenantId)

    Write-Host "Authenticating to Microsoft Defender..." -ForegroundColor Yellow

    # Check for Microsoft.Graph.Security module
    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Security)) {
        Write-Host "Installing Microsoft.Graph.Security module..." -ForegroundColor Yellow
        Install-Module Microsoft.Graph.Security -Scope CurrentUser -Force
    }

    Import-Module Microsoft.Graph.Security

    # Connect to Microsoft Graph
    Connect-MgGraph -TenantId $TenantId -Scopes "SecurityEvents.Read.All", "ThreatHunting.Read.All" -NoWelcome

    Write-Host "Executing query against Defender Advanced Hunting..." -ForegroundColor Yellow

    # Execute the hunting query
    $body = @{
        Query = $Query
    } | ConvertTo-Json

    try {
        $result = Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/security/runHuntingQuery" -Body $body -ContentType "application/json"

        if ($result.results) {
            return $result.results
        } else {
            Write-Warning "Query returned no results"
            return @()
        }
    }
    catch {
        Write-Error "Failed to execute Defender query: $_"
        throw
    }
}

function Invoke-SentinelQuery {
    param([string]$Query, [string]$TenantId, [string]$WorkspaceId)

    if ([string]::IsNullOrEmpty($WorkspaceId)) {
        Write-Error "WorkspaceId is required for Sentinel queries"
        exit 1
    }

    Write-Host "Authenticating to Azure..." -ForegroundColor Yellow

    # Check for Az.OperationalInsights module
    if (-not (Get-Module -ListAvailable -Name Az.OperationalInsights)) {
        Write-Host "Installing Az.OperationalInsights module..." -ForegroundColor Yellow
        Install-Module Az.OperationalInsights -Scope CurrentUser -Force
    }

    Import-Module Az.OperationalInsights

    # Connect to Azure
    Connect-AzAccount -TenantId $TenantId

    Write-Host "Executing query against Sentinel Log Analytics..." -ForegroundColor Yellow

    try {
        # Execute the query
        $result = Invoke-AzOperationalInsightsQuery -WorkspaceId $WorkspaceId -Query $Query -Timespan (New-TimeSpan -Days $LookbackDays)

        if ($result.Results) {
            return $result.Results
        } else {
            Write-Warning "Query returned no results"
            return @()
        }
    }
    catch {
        Write-Error "Failed to execute Sentinel query: $_"
        throw
    }
}

# Execute the appropriate query
try {
    if ($Target -eq 'Defender') {
        $Results = Invoke-DefenderQuery -Query $Query -TenantId $TenantId
    } else {
        $Results = Invoke-SentinelQuery -Query $Query -TenantId $TenantId -WorkspaceId $WorkspaceId
    }

    if ($Results.Count -eq 0) {
        Write-Warning "No devices were categorized. Check your query and data availability."
        exit 0
    }

    Write-Host ""
    Write-Host "Query completed successfully!" -ForegroundColor Green
    Write-Host "Total devices categorized: $($Results.Count)" -ForegroundColor White

    # Display summary by tier
    Write-Host ""
    Write-Host "Summary by Tier:" -ForegroundColor Cyan
    $Results | Group-Object -Property Tier | Sort-Object Name | ForEach-Object {
        $TierName = switch ($_.Name) {
            "0" { "Tier 0 (Critical Identity)" }
            "1" { "Tier 1 (Business Critical)" }
            "2" { "Tier 2 (Infrastructure)" }
            "3" { "Tier 3 (Endpoints)" }
            "99" { "Uncategorized" }
            default { "Tier $($_.Name)" }
        }
        Write-Host "  $TierName : $($_.Count) devices" -ForegroundColor White
    }

    # Display summary by category
    Write-Host ""
    Write-Host "Summary by Category:" -ForegroundColor Cyan
    $Results | Group-Object -Property Category | Sort-Object Count -Descending | ForEach-Object {
        Write-Host "  $($_.Name): $($_.Count)" -ForegroundColor White
    }

    # Export to CSV
    Write-Host ""
    Write-Host "Exporting to CSV..." -ForegroundColor Yellow
    $Results | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8

    Write-Host ""
    Write-Host "Export complete!" -ForegroundColor Green
    Write-Host "Output file: $OutputFile" -ForegroundColor White
    Write-Host ""

    # Return file path for further processing
    return $OutputFile
}
catch {
    Write-Error "Export failed: $_"
    exit 1
}
