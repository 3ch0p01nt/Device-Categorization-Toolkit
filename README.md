# Device Categorization Toolkit

Automatically categorize devices in your Microsoft E5 environment by analyzing telemetry from Defender for Endpoint, Defender for Identity, and related data sources. Designed for incident response teams who need quick visibility into device roles.

## Quick Start

### Option 1: Manual Query (Recommended for first run)

1. Open [Microsoft Defender XDR Advanced Hunting](https://security.microsoft.com/hunting)
2. Copy contents of `queries/defender/99-combined-categorization.kql`
3. Paste into Advanced Hunting query editor
4. Click "Run query"
5. Export results to CSV

### Option 2: PowerShell Export

```powershell
# For Defender XDR
.\scripts\Export-DeviceCategories.ps1 -Target Defender -TenantId "your-tenant-id"

# For Sentinel
.\scripts\Export-DeviceCategories.ps1 -Target Sentinel -TenantId "your-tenant-id" -WorkspaceId "your-workspace-id"
```

## Device Taxonomy

| Tier | Category | What it means |
|------|----------|---------------|
| **0** | Domain Controller | AD DS, critical identity infrastructure |
| **0** | Certificate Authority | PKI infrastructure (certsvc) |
| **0** | AD FS Server | Federation services |
| **0** | Entra Connect Server | Azure AD sync (AAD Connect) |
| **1** | File Server | High SMB traffic from multiple clients |
| **1** | SQL Server | Running sqlservr.exe |
| **1** | Exchange Server | Running MSExchange processes |
| **1** | SharePoint Server | Running SharePoint services |
| **1** | Web Server (IIS) | Running w3wp.exe (not Exchange/SharePoint) |
| **1** | Backup Server | Veeam, DPM, Commvault, etc. |
| **2** | WSUS Server | Windows Update Services |
| **2** | SCCM Server | Configuration Manager site server |
| **2** | Print Server | High print spooler activity |
| **2** | Jump Box / PAW | High RDP in+out, admin tools |
| **3** | IT Admin Workstation | RSAT tools, AD PowerShell |
| **3** | Developer Workstation | IDEs, compilers, dev tools |
| **3** | Kiosk / Shared Device | 5+ unique user logons |
| **3** | Standard Workstation | Default for workstation OS |

## Output Schema

| Column | Description |
|--------|-------------|
| DeviceName | Hostname |
| DeviceId | MDE device identifier |
| Tier | 0 (critical) to 3 (endpoints), 99 = uncategorized |
| Category | Primary device role |
| SecondaryCategory | Additional roles detected |
| Confidence | High/Medium/Low based on signal strength |
| Evidence | Detection signals found |
| OSPlatform | Operating system |
| LastSeen | Last activity timestamp |

## File Structure

```
Device_Categorization/
|-- queries/
|   |-- defender/
|   |   |-- 00-device-baseline.kql      # Base inventory
|   |   |-- 01-tier0-detection.kql      # DC, CA, ADFS, Entra Connect
|   |   |-- 02-tier1-detection.kql      # Servers (File, DB, Exchange, etc.)
|   |   |-- 03-tier2-detection.kql      # Infrastructure (WSUS, SCCM, Jump)
|   |   |-- 04-tier3-detection.kql      # Workstations
|   |   |-- 99-combined-categorization.kql  # All-in-one query
|   |-- sentinel/
|       |-- 99-combined-categorization.kql  # Sentinel version
|-- scripts/
|   |-- Export-DeviceCategories.ps1     # PowerShell export wrapper
|-- output/
|   |-- (CSV exports)
|-- README.md
```

## Detection Signals

### How Domain Controllers are detected
- DeviceType = "DomainController" in DeviceInfo
- Listening on ports 88 (Kerberos), 389/636 (LDAP), 3268/3269 (Global Catalog)
- Multiple methods increase confidence

### How File Servers are detected
- High volume of inbound SMB connections (port 445)
- Multiple unique client IPs connecting
- Excludes Domain Controllers (they also have SMB)

### How SQL Servers are detected
- Running sqlservr.exe, sqlagent.exe processes

### How Workstation types are detected
- **IT Admin**: RSAT tools (dsa.msc, gpmc.msc), AD PowerShell cmdlets
- **Developer**: IDEs (VS Code, Visual Studio), compilers, git, docker
- **Shared/Kiosk**: 5+ unique users with interactive logons

## Tuning the Queries

### Adjust thresholds

Edit the `let` statements at the top of queries:

```kql
let LookbackDays = 30;  // Increase for more data, decrease for recent activity only
```

Within detection logic, adjust counts:

```kql
| where SMBConnections > 100 and UniqueClients > 5  // Lower for smaller environments
```

### Add custom categories

Add new detection blocks following the pattern:

```kql
let MyCustomServers =
    DeviceProcessEvents
    | where Timestamp > ago(LookbackDays * 1d)
    | where FileName =~ "myapp.exe"
    | summarize ProcessCount = count() by DeviceId, DeviceName
    | where ProcessCount > 10
    | extend Tier = 1, Category = "My Custom Server",
             Confidence = "Medium",
             Evidence = strcat("myapp.exe count: ", ProcessCount);
```

Then add to the union in the relevant tier.

## Requirements

- **Data sources**: Microsoft Defender for Endpoint onboarded devices
- **Telemetry**: ~30 days of process and network events recommended
- **Permissions**:
  - Defender XDR: Security Reader or higher
  - Sentinel: Log Analytics Reader

## Limitations

- New devices may not categorize accurately until behavior is established
- Confidence scores are heuristic, not definitive
- Some categories require specific process telemetry (MDE must be onboarded)
- Linux/macOS devices have limited process detection

## Use Cases

### Incident Response
- Quickly identify if compromised device is Tier 0 (DC) vs Tier 3 (workstation)
- Prioritize response based on device criticality
- Understand blast radius of lateral movement

### Asset Inventory
- Baseline device roles across the environment
- Identify shadow IT or misclassified systems
- Validate naming conventions against actual usage

### Security Monitoring
- Create watchlists for high-value targets
- Build analytics rules based on tier
- Enrich alerts with device context
