<#
.SYNOPSIS
    Export device categorization results to CSV, handling the 30k row limit.

.DESCRIPTION
    This script executes the device categorization KQL query in batches to work
    around the 30,000 row limit in Defender Advanced Hunting. It splits queries
    by device name prefix and combines all results into a single CSV.

.PARAMETER TenantId
    Azure AD Tenant ID for authentication

.PARAMETER ClientId
    (Optional) App registration Client ID for non-interactive auth

.PARAMETER ClientSecret
    (Optional) App registration Client Secret for non-interactive auth

.PARAMETER OutputPath
    Path where the CSV will be saved. Defaults to ../output/

.PARAMETER LookbackDays
    Number of days to look back for device activity. Default is 30.

.PARAMETER BatchMode
    How to split the queries: 'Prefix' (by device name A-Z) or 'Tier' (by tier 0-3)

.PARAMETER CloudEnvironment
    The Microsoft cloud environment: 'Commercial', 'GCCHigh', or 'DoD'
    - Commercial: graph.microsoft.com (default)
    - GCCHigh: graph.microsoft.us
    - DoD: dod-graph.microsoft.us

.EXAMPLE
    # Interactive auth - Commercial cloud
    .\Export-DeviceCategories-Batched.ps1 -TenantId "your-tenant-id"

.EXAMPLE
    # Interactive auth - GCC High
    .\Export-DeviceCategories-Batched.ps1 -TenantId "your-tenant-id" -CloudEnvironment GCCHigh

.EXAMPLE
    # App auth (for automation)
    .\Export-DeviceCategories-Batched.ps1 -TenantId "your-tenant-id" -ClientId "app-id" -ClientSecret "secret"

.NOTES
    Requires ThreatHunting.Read.All permission

    CATEGORY DEFINITIONS:

    Tier 0 - Critical Identity Infrastructure (compromise = full domain compromise)
      - Domain Controller: Hosts Active Directory, authenticates all domain users/computers
      - Certificate Authority: Issues PKI certificates for authentication and encryption
      - AD FS Server: Provides federated authentication (SSO) for cloud/external services
      - Entra Connect Server: Syncs identities between on-prem AD and Entra ID (Azure AD)

    Tier 1 - Business Critical Servers (hosts sensitive data or critical services)
      - SQL Server: Database server running Microsoft SQL Server
      - Exchange Server: On-premises email server
      - SharePoint Server: On-premises collaboration/document management
      - Web Server (IIS): Hosts web applications via IIS (not Exchange/SharePoint)
      - File Server: High SMB traffic from multiple clients (shared file storage)
      - Backup Server: Runs backup software (Veeam, DPM, Commvault, Acronis)

    Tier 2 - Infrastructure Servers (supports IT operations)
      - WSUS Server: Windows Server Update Services (patch management)
      - SCCM Server: System Center Configuration Manager (endpoint management)
      - Jump Box / PAW: High RDP inbound AND outbound (admin access point)

    Tier 2 - Infrastructure (network and server infrastructure)
      - Network Infrastructure: DEFAULT for NativeDeviceType="NetworkDevice" (routers, switches, firewalls, APs)
      - General Purpose Server: DEFAULT for NativeDeviceType="Server" with no specific
        role detected. These are Windows Servers without identified workloads.

    Tier 3 - Endpoints (user devices and specialized equipment)
      - IT Admin Workstation: Frequent use of admin tools (RSAT, mmc.exe, PsExec)
      - Developer Workstation: Frequent use of dev tools (VS, VSCode, git, docker)
      - Security Analyst Workstation: Frequent use of security tools (Wireshark, procmon)
      - Kiosk / Shared Device: 5+ unique interactive user logons
      - Standard Workstation: DEFAULT for NativeDeviceType="Workstation" with no signals
      - Printer: DEFAULT for NativeDeviceType="Printer"
      - Mobile Device: DEFAULT for NativeDeviceType="Mobile" (phones, tablets)
      - IoT Device: DEFAULT for NativeDeviceType="IoT" (cameras, sensors)
      - Communication Device: DEFAULT for NativeDeviceType="Communication" (VoIP, video conferencing)
      - OT Device: DEFAULT for NativeDeviceType="Operational Technology" or "Industrial"
      - Unknown Device: DEFAULT when NativeDeviceType is empty or "Unknown"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$TenantId,

    [Parameter(Mandatory = $false)]
    [string]$ClientId,

    [Parameter(Mandatory = $false)]
    [string]$ClientSecret,

    [Parameter(Mandatory = $false)]
    [string]$OutputPath = (Join-Path $PSScriptRoot "..\output"),

    [Parameter(Mandatory = $false)]
    [int]$LookbackDays = 30,

    [Parameter(Mandatory = $false)]
    [ValidateSet('Prefix', 'Tier')]
    [string]$BatchMode = 'Prefix',

    [Parameter(Mandatory = $false)]
    [ValidateSet('Commercial', 'GCCHigh', 'DoD')]
    [string]$CloudEnvironment = 'Commercial'
)

$ErrorActionPreference = "Stop"

# ============================================================================
# CONFIGURATION - Set endpoints based on cloud environment
# ============================================================================

switch ($CloudEnvironment) {
    'Commercial' {
        $GraphBaseUrl = "https://graph.microsoft.com/v1.0"
        $LoginBaseUrl = "https://login.microsoftonline.com"
        $GraphScope = "https://graph.microsoft.com/.default"
        $GraphScopeInteractive = "https://graph.microsoft.com/ThreatHunting.Read.All"
    }
    'GCCHigh' {
        $GraphBaseUrl = "https://graph.microsoft.us/v1.0"
        $LoginBaseUrl = "https://login.microsoftonline.us"
        $GraphScope = "https://graph.microsoft.us/.default"
        $GraphScopeInteractive = "https://graph.microsoft.us/ThreatHunting.Read.All"
    }
    'DoD' {
        $GraphBaseUrl = "https://dod-graph.microsoft.us/v1.0"
        $LoginBaseUrl = "https://login.microsoftonline.us"
        $GraphScope = "https://dod-graph.microsoft.us/.default"
        $GraphScopeInteractive = "https://dod-graph.microsoft.us/ThreatHunting.Read.All"
    }
}

$HuntingEndpoint = "$GraphBaseUrl/security/runHuntingQuery"

# Device name prefixes for batching (covers A-Z, 0-9, and other)
$Prefixes = @(
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
    'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9'
)

# Tier values for batching
$Tiers = @(0, 1, 2, 3)

# ============================================================================
# AUTHENTICATION
# ============================================================================

function Get-AccessToken {
    param(
        [string]$TenantId,
        [string]$ClientId,
        [string]$ClientSecret,
        [string]$LoginUrl,
        [string]$Scope,
        [string]$ScopeInteractive
    )

    if ($ClientId -and $ClientSecret) {
        # App-only authentication
        Write-Host "Authenticating with app credentials..." -ForegroundColor Yellow

        $body = @{
            grant_type    = "client_credentials"
            client_id     = $ClientId
            client_secret = $ClientSecret
            scope         = $Scope
        }

        $tokenUrl = "$LoginUrl/$TenantId/oauth2/v2.0/token"
        $response = Invoke-RestMethod -Uri $tokenUrl -Method POST -Body $body -ContentType "application/x-www-form-urlencoded"
        return $response.access_token
    }
    else {
        # Interactive device code authentication
        Write-Host "Authenticating with device code flow..." -ForegroundColor Yellow

        # Use appropriate client ID for each cloud
        # Commercial: Microsoft Graph PowerShell (first-party app)
        # GCC High/DoD: Azure CLI (cross-cloud compatible first-party app)
        $appClientId = if ($LoginUrl -like "*microsoftonline.us*") {
            "04b07795-8ddb-461a-bbee-02f9e1bf7b46"  # Azure CLI - works in gov clouds
        } else {
            "14d82eec-204b-4c2f-b7e8-296a70dab67e"  # Microsoft Graph PowerShell
        }

        $deviceCodeUrl = "$LoginUrl/$TenantId/oauth2/v2.0/devicecode"
        $body = @{
            client_id = $appClientId
            scope     = $ScopeInteractive
        }

        $deviceCode = Invoke-RestMethod -Uri $deviceCodeUrl -Method POST -Body $body

        Write-Host ""
        # For gov clouds, override the URL in the message to use the correct portal
        if ($LoginUrl -like "*microsoftonline.us*") {
            Write-Host "To sign in, use a web browser to open the page:" -ForegroundColor Cyan
            Write-Host "  https://login.microsoftonline.us/common/oauth2/deviceauth" -ForegroundColor Yellow
            Write-Host "and enter the code $($deviceCode.user_code) to authenticate." -ForegroundColor Cyan
        } else {
            Write-Host $deviceCode.message -ForegroundColor Cyan
        }
        Write-Host ""

        # Poll for token
        $tokenUrl = "$LoginUrl/$TenantId/oauth2/v2.0/token"
        $tokenBody = @{
            grant_type  = "urn:ietf:params:oauth:grant-type:device_code"
            client_id   = $appClientId
            device_code = $deviceCode.device_code
        }

        $timeout = (Get-Date).AddSeconds($deviceCode.expires_in)
        while ((Get-Date) -lt $timeout) {
            Start-Sleep -Seconds $deviceCode.interval
            try {
                $response = Invoke-RestMethod -Uri $tokenUrl -Method POST -Body $tokenBody -ContentType "application/x-www-form-urlencoded"
                Write-Host "Authentication successful!" -ForegroundColor Green
                return $response.access_token
            }
            catch {
                $err = $_.ErrorDetails.Message | ConvertFrom-Json
                if ($err.error -eq "authorization_pending") {
                    Write-Host "." -NoNewline
                    continue
                }
                elseif ($err.error -eq "authorization_declined") {
                    throw "User declined authentication"
                }
                else {
                    throw $_.Exception.Message
                }
            }
        }
        throw "Authentication timed out"
    }
}

# ============================================================================
# QUERY EXECUTION
# ============================================================================

function Invoke-HuntingQuery {
    param(
        [string]$Query,
        [string]$AccessToken
    )

    $headers = @{
        "Authorization" = "Bearer $AccessToken"
        "Content-Type"  = "application/json"
    }

    $body = @{ Query = $Query } | ConvertTo-Json -Depth 10

    try {
        $response = Invoke-RestMethod -Uri $HuntingEndpoint -Method POST -Headers $headers -Body $body
        return $response.results
    }
    catch {
        $statusCode = $_.Exception.Response.StatusCode.value__
        $errorBody = $_.ErrorDetails.Message

        if ($statusCode -eq 429) {
            # Rate limited - wait and retry
            Write-Host "Rate limited, waiting 60 seconds..." -ForegroundColor Yellow
            Start-Sleep -Seconds 60
            return Invoke-HuntingQuery -Query $Query -AccessToken $AccessToken
        }
        elseif ($statusCode -eq 400) {
            Write-Warning "Query error: $errorBody"
            return @()
        }
        else {
            throw "API Error ($statusCode): $errorBody"
        }
    }
}

# ============================================================================
# BASE QUERY (without the final project/order)
# ============================================================================

$BaseQuery = @"
let LookbackDays = $LookbackDays;
let BaselineDevices = DeviceInfo | where Timestamp > ago(LookbackDays * 1d) | summarize LastSeen = max(Timestamp), arg_max(Timestamp, OSPlatform, OSVersion, OSArchitecture, DeviceType, MachineGroup, IsAzureADJoined, JoinType) by DeviceId, DeviceName | extend IsServerOS = coalesce(OSPlatform has_any ("Server", "WindowsServer") or OSVersion has_any ("Server", "2016", "2019", "2022", "2012"), false), NativeDeviceType = DeviceType;
let DCsByDeviceType = DeviceInfo | where Timestamp > ago(LookbackDays * 1d) | where DeviceType == "DomainController" | distinct DeviceId, DeviceName | extend Method = "DeviceType";
let DCsByKerberos = DeviceNetworkEvents | where Timestamp > ago(LookbackDays * 1d) | where LocalPort == 88 | where LocalIPType == "FourToSixMapping" | distinct DeviceId, DeviceName | extend Method = "Kerberos";
let DCsByPorts = DeviceNetworkEvents | where Timestamp > ago(LookbackDays * 1d) | where ActionType == "ListeningConnectionCreated" | where LocalPort in (88, 389, 636) | summarize Ports = make_set(LocalPort) by DeviceId, DeviceName | where set_has_element(Ports, 88) and (set_has_element(Ports, 389) or set_has_element(Ports, 636)) | extend Method = "DCPorts";
let DomainControllers = union DCsByDeviceType, DCsByKerberos, DCsByPorts | summarize Methods = make_set(Method) by DeviceId, DeviceName | extend Tier = 0, Category = "Domain Controller", Confidence = iff(array_length(Methods) > 1, "High", "Medium"), DetectionMethod = "MultiSignal", Evidence = strcat("Serves Kerberos/LDAP authentication services. Detection: ", tostring(Methods));
let CertificateAuthorities = DeviceProcessEvents | where Timestamp > ago(LookbackDays * 1d) | where FileName =~ "certsvc.exe" | summarize ProcessCount = count() by DeviceId, DeviceName | where ProcessCount > 5 | extend Tier = 0, Category = "Certificate Authority", Confidence = iff(ProcessCount > 50, "High", "Medium"), DetectionMethod = "ProcessBased", Evidence = "Runs certsvc.exe (Certificate Services) - issues PKI certificates for the organization.";
let ADFSServers = DeviceProcessEvents | where Timestamp > ago(LookbackDays * 1d) | where FileName =~ "Microsoft.IdentityServer.ServiceHost.exe" | summarize ProcessCount = count() by DeviceId, DeviceName | where ProcessCount > 10 | extend Tier = 0, Category = "AD FS Server", Confidence = "Medium", DetectionMethod = "ProcessBased", Evidence = "Runs AD FS federation service - handles federated authentication and SSO.";
let EntraConnectServers = DeviceProcessEvents | where Timestamp > ago(LookbackDays * 1d) | where FileName in~ ("miiserver.exe", "AzureADConnect.exe", "ADSync.exe") | summarize ProcessCount = count() by DeviceId, DeviceName | where ProcessCount > 10 | extend Tier = 0, Category = "Entra Connect Server", Confidence = "High", DetectionMethod = "ProcessBased", Evidence = "Runs Entra Connect sync - bridges on-prem AD with cloud identity. Compromise enables cloud tenant takeover.";
let SQLServers = DeviceProcessEvents | where Timestamp > ago(LookbackDays * 1d) | where FileName in~ ("sqlservr.exe", "sqlagent.exe") | summarize ProcessCount = count() by DeviceId, DeviceName | where ProcessCount > 20 | extend Tier = 1, Category = "SQL Server", Confidence = iff(ProcessCount > 200, "High", "Medium"), DetectionMethod = "ProcessBased", Evidence = "Runs SQL Server database engine - hosts organizational databases with business-critical data.";
let ExchangeServers = DeviceProcessEvents | where Timestamp > ago(LookbackDays * 1d) | where FileName has "MSExchange" or FileName =~ "EdgeTransport.exe" | summarize ProcessCount = count() by DeviceId, DeviceName | where ProcessCount > 50 | extend Tier = 1, Category = "Exchange Server", Confidence = iff(ProcessCount > 500, "High", "Medium"), DetectionMethod = "ProcessBased", Evidence = "Runs Exchange mail services - processes organizational email containing sensitive communications.";
let SharePointServers = DeviceProcessEvents | where Timestamp > ago(LookbackDays * 1d) | where FileName in~ ("OWSTIMER.EXE", "SPUCWorkerProcess.exe") or (FileName =~ "w3wp.exe" and ProcessCommandLine has "SharePoint") | summarize ProcessCount = count() by DeviceId, DeviceName | where ProcessCount > 20 | extend Tier = 1, Category = "SharePoint Server", Confidence = iff(ProcessCount > 200, "High", "Medium"), DetectionMethod = "ProcessBased", Evidence = "Runs SharePoint services - hosts document libraries and collaboration sites.";
let WebServers = DeviceProcessEvents | where Timestamp > ago(LookbackDays * 1d) | where FileName =~ "w3wp.exe" | where not(ProcessCommandLine has_any ("Exchange", "SharePoint")) | summarize ProcessCount = count() by DeviceId, DeviceName | where ProcessCount > 50 | extend Tier = 1, Category = "Web Server (IIS)", Confidence = iff(ProcessCount > 500, "High", "Medium"), DetectionMethod = "ProcessBased", Evidence = "Runs IIS web server - hosts web applications.";
let FileServers = DeviceNetworkEvents | where Timestamp > ago(LookbackDays * 1d) | where LocalPort == 445 | summarize SMBConnections = count(), UniqueClients = dcount(RemoteIP) by DeviceId, DeviceName | where SMBConnections > 100 and UniqueClients > 5 | extend Tier = 1, Category = "File Server", Confidence = case(UniqueClients > 50, "High", UniqueClients > 20, "Medium", "Low"), DetectionMethod = "NetworkBehavior", Evidence = strcat("Received ", SMBConnections, " SMB connections from ", UniqueClients, " clients - serves as central file storage.");
let BackupServers = DeviceProcessEvents | where Timestamp > ago(LookbackDays * 1d) | where FileName in~ ("Veeam.Backup.Service.exe", "VeeamAgent.exe", "DPMRA.exe", "cvd.exe", "bprd.exe", "AcronisAgent.exe") | summarize ProcessCount = count() by DeviceId, DeviceName | where ProcessCount > 10 | extend Tier = 1, Category = "Backup Server", Confidence = iff(ProcessCount > 100, "High", "Medium"), DetectionMethod = "ProcessBased", Evidence = "Runs backup software - contains copies of organizational data.";
let WSUSServers = DeviceProcessEvents | where Timestamp > ago(LookbackDays * 1d) | where FileName =~ "WsusService.exe" | summarize ProcessCount = count() by DeviceId, DeviceName | where ProcessCount > 10 | extend Tier = 2, Category = "WSUS Server", Confidence = iff(ProcessCount > 100, "High", "Medium"), DetectionMethod = "ProcessBased", Evidence = "Runs WSUS - distributes Windows updates to endpoints.";
let SCCMServers = DeviceProcessEvents | where Timestamp > ago(LookbackDays * 1d) | where FileName in~ ("smsexec.exe", "sitecomp.exe", "distmgr.exe", "smsdbmon.exe") | summarize ProcessCount = count() by DeviceId, DeviceName | where ProcessCount > 20 | extend Tier = 2, Category = "SCCM Server", Confidence = iff(ProcessCount > 200, "High", "Medium"), DetectionMethod = "ProcessBased", Evidence = "Runs SCCM/MECM - manages endpoint configuration and software deployment.";
let JumpBoxes = DeviceNetworkEvents | where Timestamp > ago(LookbackDays * 1d) | where LocalPort == 3389 or RemotePort == 3389 | summarize RDPInbound = countif(LocalPort == 3389), RDPOutbound = countif(RemotePort == 3389) by DeviceId, DeviceName | where RDPInbound > 50 and RDPOutbound > 20 | extend Tier = 2, Category = "Jump Box / PAW", Confidence = case(RDPInbound > 200 and RDPOutbound > 100, "High", "Medium"), DetectionMethod = "NetworkBehavior", Evidence = strcat("High RDP traffic (in:", RDPInbound, " out:", RDPOutbound, ") - used as admin jump point to other systems.");
let AdminWorkstations = DeviceProcessEvents | where Timestamp > ago(LookbackDays * 1d) | where FileName in~ ("dsa.msc", "dnsmgmt.msc", "gpmc.msc", "ServerManager.exe", "PsExec.exe", "PsExec64.exe", "mmc.exe") | summarize AdminToolCount = count(), Tools = make_set(FileName) by DeviceId, DeviceName | where AdminToolCount > 20 | join kind=inner (BaselineDevices | where not(IsServerOS) | project DeviceId) on DeviceId | extend Tier = 3, Category = "IT Admin Workstation", Confidence = iff(AdminToolCount > 100, "High", "Medium"), DetectionMethod = "ToolUsage", Evidence = strcat("Runs admin tools (", tostring(Tools), ") - used by IT staff to manage infrastructure.");
let DeveloperWorkstations = DeviceProcessEvents | where Timestamp > ago(LookbackDays * 1d) | where FileName in~ ("devenv.exe", "Code.exe", "rider64.exe", "idea64.exe", "pycharm64.exe", "git.exe", "node.exe", "python.exe", "docker.exe", "dotnet.exe", "npm.exe") | summarize DevToolCount = count(), Tools = make_set(FileName) by DeviceId, DeviceName | where DevToolCount > 50 | join kind=inner (BaselineDevices | where not(IsServerOS) | project DeviceId) on DeviceId | extend Tier = 3, Category = "Developer Workstation", Confidence = iff(DevToolCount > 500, "High", "Medium"), DetectionMethod = "ToolUsage", Evidence = strcat("Runs dev tools (", tostring(Tools), ") - has access to source code and deployment pipelines.");
let SecurityWorkstations = DeviceProcessEvents | where Timestamp > ago(LookbackDays * 1d) | where FileName in~ ("Wireshark.exe", "procmon.exe", "procexp.exe", "autoruns.exe", "tcpview.exe", "Fiddler.exe", "nmap.exe") | summarize SecToolCount = count() by DeviceId, DeviceName | where SecToolCount > 10 | join kind=inner (BaselineDevices | where not(IsServerOS) | project DeviceId) on DeviceId | extend Tier = 3, Category = "Security Analyst Workstation", Confidence = iff(SecToolCount > 50, "High", "Medium"), DetectionMethod = "ToolUsage", Evidence = "Runs security analysis tools - used for security operations.";
let SharedDevices = DeviceLogonEvents | where Timestamp > ago(LookbackDays * 1d) | where LogonType in ("Interactive", "RemoteInteractive") | where AccountName !in~ ("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE") | summarize UniqueUsers = dcount(AccountName) by DeviceId, DeviceName | where UniqueUsers >= 5 | join kind=inner (BaselineDevices | where not(IsServerOS) | project DeviceId) on DeviceId | extend Tier = 3, Category = "Kiosk / Shared Device", Confidence = iff(UniqueUsers >= 15, "High", "Medium"), DetectionMethod = "LogonBehavior", Evidence = strcat(UniqueUsers, " users logged in - shared device (conference room, training lab, kiosk).");
let GenericServers = BaselineDevices | where IsServerOS | where NativeDeviceType =~ "Server" or isempty(NativeDeviceType) | project DeviceId, DeviceName | extend Tier = 2, Category = "Generic Server", Confidence = "Low", DetectionMethod = "OSBased", Evidence = "Server OS detected but no specific role identified.";
let StandardWorkstations = BaselineDevices | where not(IsServerOS) | where NativeDeviceType =~ "Workstation" or isempty(NativeDeviceType) | project DeviceId, DeviceName | extend Tier = 3, Category = "Standard Workstation", Confidence = "Low", DetectionMethod = "Default", Evidence = "Standard endpoint with no specialized role detected.";
let NetworkInfrastructure = BaselineDevices | where NativeDeviceType =~ "NetworkDevice" | project DeviceId, DeviceName | extend Tier = 2, Category = "Network Infrastructure", Confidence = "Medium", DetectionMethod = "DeviceType", Evidence = "Defender identifies as network device (router, switch, firewall, AP).";
let PrinterDevices = BaselineDevices | where NativeDeviceType =~ "Printer" | project DeviceId, DeviceName | extend Tier = 3, Category = "Printer", Confidence = "Medium", DetectionMethod = "DeviceType", Evidence = "Defender identifies as printer device.";
let MobileDevices = BaselineDevices | where NativeDeviceType =~ "Mobile" | project DeviceId, DeviceName | extend Tier = 3, Category = "Mobile Device", Confidence = "Medium", DetectionMethod = "DeviceType", Evidence = "Defender identifies as mobile device (phone, tablet).";
let IoTDevices = BaselineDevices | where NativeDeviceType in~ ("IoT", "Communication", "Operational Technology", "Industrial") | project DeviceId, DeviceName, NativeDeviceType | extend Tier = 3, Category = case(NativeDeviceType =~ "Communication", "Communication Device", NativeDeviceType =~ "Operational Technology", "OT Device", NativeDeviceType =~ "Industrial", "Industrial Control System", "IoT Device"), Confidence = "Medium", DetectionMethod = "DeviceType", Evidence = strcat("Defender identifies as ", NativeDeviceType, " (VoIP, camera, sensor, or industrial equipment).");
let UnknownDevices = BaselineDevices | where NativeDeviceType =~ "Unknown" | project DeviceId, DeviceName | extend Tier = 3, Category = "Unknown Device", Confidence = "Low", DetectionMethod = "Default", Evidence = "Device type could not be determined by Defender.";
let AllCategorized = union DomainControllers, CertificateAuthorities, ADFSServers, EntraConnectServers, SQLServers, ExchangeServers, SharePointServers, WebServers, FileServers, BackupServers, WSUSServers, SCCMServers, JumpBoxes, AdminWorkstations, DeveloperWorkstations, SecurityWorkstations, SharedDevices;
let Tier0 = union DomainControllers, CertificateAuthorities, ADFSServers, EntraConnectServers;
let Tier1 = union SQLServers, ExchangeServers, SharePointServers, WebServers, FileServers, BackupServers;
let Tier2 = union WSUSServers, SCCMServers, JumpBoxes, GenericServers, NetworkInfrastructure;
let Tier3 = union AdminWorkstations, DeveloperWorkstations, SecurityWorkstations, SharedDevices, StandardWorkstations, PrinterDevices, MobileDevices, IoTDevices, UnknownDevices;
let AllWithFallback = union AllCategorized, (BaselineDevices | join kind=leftanti (AllCategorized | project DeviceId) on DeviceId | extend Tier = case(NativeDeviceType =~ "NetworkDevice", 2, IsServerOS, 2, 3), Category = case(NativeDeviceType =~ "Workstation", "Standard Workstation", NativeDeviceType =~ "Server", "General Purpose Server", NativeDeviceType =~ "DomainController", "Domain Controller", NativeDeviceType =~ "NetworkDevice", "Network Infrastructure", NativeDeviceType =~ "Printer", "Printer", NativeDeviceType =~ "Mobile", "Mobile Device", NativeDeviceType =~ "IoT", "IoT Device", NativeDeviceType =~ "Communication", "Communication Device", NativeDeviceType in~ ("Operational Technology", "Industrial"), "OT Device", isempty(NativeDeviceType) or NativeDeviceType =~ "Unknown", "Unknown Device", strcat(NativeDeviceType, " Device")), Confidence = "Low", DetectionMethod = "Default", Evidence = "Categorized by NativeDeviceType - no specific role detected.");
AllWithFallback
| summarize arg_min(Tier, Category, Confidence, Evidence, DetectionMethod), AllCategories = make_set(Category) by DeviceId, DeviceName
| join kind=leftouter (BaselineDevices | project DeviceId, DeviceName, OSPlatform, OSVersion, NativeDeviceType, MachineGroup, LastSeen, IsAzureADJoined, JoinType) on DeviceId, DeviceName
| extend OtherRoles = set_difference(AllCategories, pack_array(Category)), AdditionalRoles = iff(array_length(set_difference(AllCategories, pack_array(Category))) > 0, strcat_array(set_difference(AllCategories, pack_array(Category)), ", "), ""), RoleCount = array_length(AllCategories)
| project DeviceName, DeviceId, Tier, Category, AdditionalRoles, RoleCount, Confidence, DetectionMethod, Evidence, NativeDeviceType, OSPlatform, OSVersion, MachineGroup, LastSeen, IsAzureADJoined, JoinType
"@

# ============================================================================
# MAIN EXECUTION
# ============================================================================

Write-Host ""
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "  Device Categorization Export (Batched)    " -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Tenant ID:    $TenantId" -ForegroundColor White
Write-Host "Cloud:        $CloudEnvironment" -ForegroundColor White
Write-Host "Graph URL:    $GraphBaseUrl" -ForegroundColor Gray
Write-Host "Lookback:     $LookbackDays days" -ForegroundColor White
Write-Host "Batch Mode:   $BatchMode" -ForegroundColor White
Write-Host ""

# Ensure output directory exists
if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

# Get access token
$AccessToken = Get-AccessToken -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret -LoginUrl $LoginBaseUrl -Scope $GraphScope -ScopeInteractive $GraphScopeInteractive

# Collect all results
$AllResults = @()
$TotalDevices = 0

if ($BatchMode -eq 'Prefix') {
    # Query by device name prefix
    Write-Host ""
    Write-Host "Querying devices by name prefix..." -ForegroundColor Yellow

    $BatchCount = $Prefixes.Count
    $CurrentBatch = 0

    foreach ($Prefix in $Prefixes) {
        $CurrentBatch++
        $PercentComplete = [math]::Round(($CurrentBatch / $BatchCount) * 100)

        Write-Progress -Activity "Exporting Device Categories" -Status "Processing prefix '$Prefix' ($CurrentBatch of $BatchCount)" -PercentComplete $PercentComplete

        # Add filter for this prefix
        $FilteredQuery = $BaseQuery + "`n| where DeviceName startswith_cs `"$Prefix`" or DeviceName startswith_cs `"$($Prefix.ToLower())`""
        $FilteredQuery += "`n| order by Tier asc, Category asc, DeviceName asc"

        $Results = Invoke-HuntingQuery -Query $FilteredQuery -AccessToken $AccessToken

        if ($Results -and $Results.Count -gt 0) {
            $AllResults += $Results
            $TotalDevices += $Results.Count
            Write-Host "  Prefix '$Prefix': $($Results.Count) devices" -ForegroundColor Gray
        }

        # Small delay to avoid rate limiting
        Start-Sleep -Milliseconds 500
    }

    # Also query for devices starting with special characters or other
    Write-Host "  Querying remaining devices..." -ForegroundColor Gray
    $OtherQuery = $BaseQuery + @"
`n| where not(DeviceName startswith_cs "A") and not(DeviceName startswith_cs "a")
    and not(DeviceName startswith_cs "B") and not(DeviceName startswith_cs "b")
    and not(DeviceName startswith_cs "C") and not(DeviceName startswith_cs "c")
    and not(DeviceName startswith_cs "D") and not(DeviceName startswith_cs "d")
    and not(DeviceName startswith_cs "E") and not(DeviceName startswith_cs "e")
    and not(DeviceName startswith_cs "F") and not(DeviceName startswith_cs "f")
    and not(DeviceName startswith_cs "G") and not(DeviceName startswith_cs "g")
    and not(DeviceName startswith_cs "H") and not(DeviceName startswith_cs "h")
    and not(DeviceName startswith_cs "I") and not(DeviceName startswith_cs "i")
    and not(DeviceName startswith_cs "J") and not(DeviceName startswith_cs "j")
    and not(DeviceName startswith_cs "K") and not(DeviceName startswith_cs "k")
    and not(DeviceName startswith_cs "L") and not(DeviceName startswith_cs "l")
    and not(DeviceName startswith_cs "M") and not(DeviceName startswith_cs "m")
    and not(DeviceName startswith_cs "N") and not(DeviceName startswith_cs "n")
    and not(DeviceName startswith_cs "O") and not(DeviceName startswith_cs "o")
    and not(DeviceName startswith_cs "P") and not(DeviceName startswith_cs "p")
    and not(DeviceName startswith_cs "Q") and not(DeviceName startswith_cs "q")
    and not(DeviceName startswith_cs "R") and not(DeviceName startswith_cs "r")
    and not(DeviceName startswith_cs "S") and not(DeviceName startswith_cs "s")
    and not(DeviceName startswith_cs "T") and not(DeviceName startswith_cs "t")
    and not(DeviceName startswith_cs "U") and not(DeviceName startswith_cs "u")
    and not(DeviceName startswith_cs "V") and not(DeviceName startswith_cs "v")
    and not(DeviceName startswith_cs "W") and not(DeviceName startswith_cs "w")
    and not(DeviceName startswith_cs "X") and not(DeviceName startswith_cs "x")
    and not(DeviceName startswith_cs "Y") and not(DeviceName startswith_cs "y")
    and not(DeviceName startswith_cs "Z") and not(DeviceName startswith_cs "z")
    and not(DeviceName startswith_cs "0") and not(DeviceName startswith_cs "1")
    and not(DeviceName startswith_cs "2") and not(DeviceName startswith_cs "3")
    and not(DeviceName startswith_cs "4") and not(DeviceName startswith_cs "5")
    and not(DeviceName startswith_cs "6") and not(DeviceName startswith_cs "7")
    and not(DeviceName startswith_cs "8") and not(DeviceName startswith_cs "9")
| order by Tier asc, Category asc, DeviceName asc
"@
    $OtherResults = Invoke-HuntingQuery -Query $OtherQuery -AccessToken $AccessToken
    if ($OtherResults -and $OtherResults.Count -gt 0) {
        $AllResults += $OtherResults
        $TotalDevices += $OtherResults.Count
        Write-Host "  Other prefixes: $($OtherResults.Count) devices" -ForegroundColor Gray
    }
}
else {
    # Query by Tier
    Write-Host ""
    Write-Host "Querying devices by Tier..." -ForegroundColor Yellow

    foreach ($TierNum in $Tiers) {
        Write-Progress -Activity "Exporting Device Categories" -Status "Processing Tier $TierNum" -PercentComplete (($TierNum + 1) / 4 * 100)

        $FilteredQuery = $BaseQuery + "`n| where Tier == $TierNum"
        $FilteredQuery += "`n| order by Category asc, DeviceName asc"

        $Results = Invoke-HuntingQuery -Query $FilteredQuery -AccessToken $AccessToken

        if ($Results -and $Results.Count -gt 0) {
            $AllResults += $Results
            $TotalDevices += $Results.Count
            Write-Host "  Tier $TierNum : $($Results.Count) devices" -ForegroundColor Gray
        }

        Start-Sleep -Milliseconds 500
    }
}

Write-Progress -Activity "Exporting Device Categories" -Completed

# Remove duplicates (in case a device appeared in multiple batches)
Write-Host ""
Write-Host "Removing duplicates..." -ForegroundColor Yellow
$UniqueResults = $AllResults | Group-Object -Property DeviceId | ForEach-Object { $_.Group | Select-Object -First 1 }

Write-Host ""
Write-Host "=============================================" -ForegroundColor Green
Write-Host "  Export Complete!" -ForegroundColor Green
Write-Host "=============================================" -ForegroundColor Green
Write-Host ""
Write-Host "Total devices: $($UniqueResults.Count)" -ForegroundColor White

# Summary by Tier
Write-Host ""
Write-Host "Summary by Tier:" -ForegroundColor Cyan
$UniqueResults | Group-Object -Property Tier | Sort-Object Name | ForEach-Object {
    $TierName = switch ($_.Name) {
        "0" { "Tier 0 (Critical Identity)" }
        "1" { "Tier 1 (Business Critical)" }
        "2" { "Tier 2 (Infrastructure)" }
        "3" { "Tier 3 (Endpoints)" }
        default { "Tier $($_.Name)" }
    }
    Write-Host "  $TierName : $($_.Count) devices" -ForegroundColor White
}

# Summary by Category
Write-Host ""
Write-Host "Summary by Category:" -ForegroundColor Cyan
$UniqueResults | Group-Object -Property Category | Sort-Object Count -Descending | Select-Object -First 15 | ForEach-Object {
    Write-Host "  $($_.Name): $($_.Count)" -ForegroundColor White
}

# Export to CSV
$Timestamp = Get-Date -Format "yyyy-MM-dd_HHmmss"
$OutputFile = Join-Path $OutputPath "DeviceCategories_Batched_${Timestamp}.csv"

Write-Host ""
Write-Host "Exporting to CSV..." -ForegroundColor Yellow
$UniqueResults | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8

Write-Host ""
Write-Host "Output file: $OutputFile" -ForegroundColor Green
Write-Host ""

# Return file path
return $OutputFile
