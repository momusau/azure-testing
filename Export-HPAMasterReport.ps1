#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Identity.Governance, Microsoft.Graph.Groups, Microsoft.Graph.Users, Az.Accounts, Az.Resources

<#
.SYNOPSIS
    Generates a Highly Privileged Accounts (HPA) Master Report across Entra and Azure RBAC.

.DESCRIPTION
    Produces a single CSV covering:
      A. Entra Directory Roles (active assignments)
      B. Entra PIM Eligible Roles
      C. Entra PIM Active Schedules
      D. Azure RBAC Role Assignments
      E. Azure RBAC PIM (eligible + scheduled-active, graceful skip if unavailable)

    Groups are expanded to effective user members. Rows are deduplicated before export.

.NOTES
    Prerequisites:
      Connect-MgGraph -Scopes "RoleManagement.Read.All","Group.Read.All","User.Read.All","Directory.Read.All"
      Connect-AzAccount

    Role lists are baseline/interim — edit the configuration arrays below as Security guidance evolves.
#>

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ─────────────────────────────────────────────────────────────────────────────
# 1. CONFIGURATION — edit these lists as guidance evolves
# ─────────────────────────────────────────────────────────────────────────────

# Entra directory roles considered highly privileged (display names)
$EntraHighlyPrivilegedRoles = @(
    'Global Administrator'
    'Privileged Role Administrator'
    'Privileged Authentication Administrator'
    'Security Administrator'
    'Exchange Administrator'
    'SharePoint Administrator'
    'User Administrator'
    'Helpdesk Administrator'
    'Authentication Administrator'
    'Cloud Application Administrator'
    'Application Administrator'
    'Intune Administrator'
)

# Azure RBAC roles considered highly privileged (role names)
$AzureRBACHighlyPrivilegedRoles = @(
    'Owner'
    'Contributor'
    'User Access Administrator'
)

# ─────────────────────────────────────────────────────────────────────────────
# 2. CONNECTION VALIDATION
# ─────────────────────────────────────────────────────────────────────────────

$mgCtx = Get-MgContext
if (-not $mgCtx) {
    throw "Not connected to Microsoft Graph. Run Connect-MgGraph -Scopes 'RoleManagement.Read.All','Group.Read.All','User.Read.All','Directory.Read.All' first."
}
Write-Host "Graph context : $($mgCtx.Account)  Tenant: $($mgCtx.TenantId)"

$azCtx = Get-AzContext
if (-not $azCtx) {
    throw "Not connected to Azure. Run Connect-AzAccount first."
}
Write-Host "Az context    : $($azCtx.Account.Id)  Tenant: $($azCtx.Tenant.Id)"

$tenantId  = $mgCtx.TenantId
$reportUtc = (Get-Date).ToUniversalTime().ToString('o')

# ─────────────────────────────────────────────────────────────────────────────
# 3. CACHING INFRASTRUCTURE
# ─────────────────────────────────────────────────────────────────────────────

$userCache        = @{}   # principalId → user object (or $null sentinel)
$groupCache       = @{}   # groupId     → group object (or $null sentinel)
$groupMemberCache = @{}   # groupId     → list of transitive user members

function Get-CachedUser {
    param([string]$Id)
    if (-not $userCache.ContainsKey($Id)) {
        $userCache[$Id] = try { Get-MgUser -UserId $Id -ErrorAction Stop } catch { $null }
    }
    return $userCache[$Id]
}

function Get-CachedGroup {
    param([string]$Id)
    if (-not $groupCache.ContainsKey($Id)) {
        $groupCache[$Id] = try { Get-MgGroup -GroupId $Id -Property 'Id,DisplayName,IsAssignableToRole' -ErrorAction Stop } catch { $null }
    }
    return $groupCache[$Id]
}

function Get-CachedGroupMembers {
    param([string]$GroupId)
    if (-not $groupMemberCache.ContainsKey($GroupId)) {
        $members = Get-MgGroupTransitiveMember -GroupId $GroupId -All |
            Where-Object { $_.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.user' } |
            ForEach-Object {
                [pscustomobject]@{
                    Id                = $_.Id
                    UserPrincipalName = $_.AdditionalProperties.userPrincipalName
                    DisplayName       = $_.AdditionalProperties.displayName
                }
            }
        $groupMemberCache[$GroupId] = @($members)
    }
    return $groupMemberCache[$GroupId]
}

# ─────────────────────────────────────────────────────────────────────────────
# 4. ROW BUILDER
# ─────────────────────────────────────────────────────────────────────────────

function New-ReportRow {
    param(
        [string]$ControlPlane,
        [string]$RoleName,
        [string]$RoleDefinitionId,
        [string]$Scope,
        [string]$AssignmentCategory,
        [string]$AssignmentState,
        [string]$PrincipalType,
        [string]$EffectiveUserId,
        [string]$EffectiveUserUPN,
        [string]$EffectiveUserDisplayName,
        [string]$SourceGroupId,
        [string]$SourceGroupDisplayName,
        [string]$IsRoleAssignableGroup,
        [string]$Notes
    )
    [pscustomobject]@{
        ReportGeneratedUtc       = $reportUtc
        TenantId                 = $tenantId
        ControlPlane             = $ControlPlane
        RoleName                 = $RoleName
        RoleDefinitionId         = $RoleDefinitionId
        Scope                    = $Scope
        AssignmentCategory       = $AssignmentCategory
        AssignmentState          = $AssignmentState
        PrincipalType            = $PrincipalType
        EffectiveUserId          = $EffectiveUserId
        EffectiveUserUPN         = $EffectiveUserUPN
        EffectiveUserDisplayName = $EffectiveUserDisplayName
        SourceGroupId            = $SourceGroupId
        SourceGroupDisplayName   = $SourceGroupDisplayName
        IsRoleAssignableGroup    = $IsRoleAssignableGroup
        Notes                    = $Notes
    }
}

# Helper: resolve a principal and append rows for a given control-plane assignment
function Resolve-PrincipalAndAddRows {
    param(
        [System.Collections.Generic.List[object]]$Rows,
        [string]$PrincipalId,
        [string]$ControlPlane,
        [string]$RoleName,
        [string]$RoleDefinitionId,
        [string]$Scope,
        [string]$AssignmentCategory,
        [string]$AssignmentState,
        [string]$Notes
    )

    # Try user first
    $user = Get-CachedUser -Id $PrincipalId
    if ($user) {
        $Rows.Add((New-ReportRow `
            -ControlPlane $ControlPlane -RoleName $RoleName -RoleDefinitionId $RoleDefinitionId `
            -Scope $Scope -AssignmentCategory 'DirectAssignment' -AssignmentState $AssignmentState `
            -PrincipalType 'User' -EffectiveUserId $user.Id `
            -EffectiveUserUPN $user.UserPrincipalName -EffectiveUserDisplayName $user.DisplayName `
            -SourceGroupId '' -SourceGroupDisplayName '' -IsRoleAssignableGroup '' -Notes $Notes))
        return
    }

    # Try group
    $group = Get-CachedGroup -Id $PrincipalId
    if ($group) {
        $isRAG = if ($group.IsAssignableToRole) { 'Yes' } else { 'No' }
        $members = Get-CachedGroupMembers -GroupId $group.Id
        if ($members.Count -eq 0) {
            # Empty group — record the group itself so it's visible
            $Rows.Add((New-ReportRow `
                -ControlPlane $ControlPlane -RoleName $RoleName -RoleDefinitionId $RoleDefinitionId `
                -Scope $Scope -AssignmentCategory 'GroupAssignmentExpanded' -AssignmentState $AssignmentState `
                -PrincipalType 'Group (empty)' -EffectiveUserId '' -EffectiveUserUPN '' `
                -EffectiveUserDisplayName '' -SourceGroupId $group.Id `
                -SourceGroupDisplayName $group.DisplayName -IsRoleAssignableGroup $isRAG `
                -Notes "$Notes; Group has no transitive user members"))
            return
        }
        foreach ($m in $members) {
            $Rows.Add((New-ReportRow `
                -ControlPlane $ControlPlane -RoleName $RoleName -RoleDefinitionId $RoleDefinitionId `
                -Scope $Scope -AssignmentCategory 'GroupAssignmentExpanded' -AssignmentState $AssignmentState `
                -PrincipalType 'User' -EffectiveUserId $m.Id `
                -EffectiveUserUPN $m.UserPrincipalName -EffectiveUserDisplayName $m.DisplayName `
                -SourceGroupId $group.Id -SourceGroupDisplayName $group.DisplayName `
                -IsRoleAssignableGroup $isRAG -Notes $Notes))
        }
        return
    }

    # Service principal or unknown
    $Rows.Add((New-ReportRow `
        -ControlPlane $ControlPlane -RoleName $RoleName -RoleDefinitionId $RoleDefinitionId `
        -Scope $Scope -AssignmentCategory 'DirectAssignment' -AssignmentState $AssignmentState `
        -PrincipalType 'ServicePrincipal' -EffectiveUserId $PrincipalId `
        -EffectiveUserUPN '' -EffectiveUserDisplayName '' `
        -SourceGroupId '' -SourceGroupDisplayName '' -IsRoleAssignableGroup '' `
        -Notes "$Notes; Could not resolve as user or group — likely a service principal"))
}

# ─────────────────────────────────────────────────────────────────────────────
# 5. DATA COLLECTION
# ─────────────────────────────────────────────────────────────────────────────

$rows = [System.Collections.Generic.List[object]]::new()

# --- Build role-definition lookup for Entra ---
Write-Host "`nLoading Entra role definitions..."
$allRoleDefs = Get-MgRoleManagementDirectoryRoleDefinition -All
$roleNameById = @{}
$roleIdByName = @{}
foreach ($rd in $allRoleDefs) {
    $roleNameById[$rd.Id] = $rd.DisplayName
    $roleIdByName[$rd.DisplayName] = $rd.Id
}

# Filter to configured highly-privileged role IDs
$hpRoleIds = @{}
foreach ($name in $EntraHighlyPrivilegedRoles) {
    if ($roleIdByName.ContainsKey($name)) {
        $hpRoleIds[$roleIdByName[$name]] = $name
    } else {
        Write-Warning "Entra role not found: '$name' — skipping"
    }
}

# ── A. Entra Directory Roles (Active Assignments) ────────────────────────────

Write-Host "Section A: Entra Directory Roles — active assignments..."
$entraAssignments = Get-MgRoleManagementDirectoryRoleAssignment -All
$filtered = $entraAssignments | Where-Object { $hpRoleIds.ContainsKey($_.RoleDefinitionId) }
$total = @($filtered).Count; $i = 0
foreach ($a in $filtered) {
    Write-Host "`r  Processing $((++$i)) / $total ..." -NoNewline
    Resolve-PrincipalAndAddRows -Rows $rows `
        -PrincipalId $a.PrincipalId `
        -ControlPlane 'EntraDirectoryRole' `
        -RoleName $hpRoleIds[$a.RoleDefinitionId] `
        -RoleDefinitionId $a.RoleDefinitionId `
        -Scope $(if ($a.DirectoryScopeId) { $a.DirectoryScopeId } else { '/' }) `
        -AssignmentCategory 'DirectAssignment' `
        -AssignmentState 'Active' `
        -Notes ''
}
Write-Host "`r  Done: $total assignments processed.       "

# ── B. Entra PIM Eligible Roles ──────────────────────────────────────────────

Write-Host "Section B: Entra PIM — eligible role schedules..."
try {
    $eligSchedules = Get-MgRoleManagementDirectoryRoleEligibilityScheduleInstance -All
    $filteredElig = $eligSchedules | Where-Object { $hpRoleIds.ContainsKey($_.RoleDefinitionId) }
    $total = @($filteredElig).Count; $i = 0
    foreach ($e in $filteredElig) {
        Write-Host "`r  Processing $((++$i)) / $total ..." -NoNewline
        Resolve-PrincipalAndAddRows -Rows $rows `
            -PrincipalId $e.PrincipalId `
            -ControlPlane 'EntraDirectoryRole' `
            -RoleName $hpRoleIds[$e.RoleDefinitionId] `
            -RoleDefinitionId $e.RoleDefinitionId `
            -Scope $(if ($e.DirectoryScopeId) { $e.DirectoryScopeId } else { '/' }) `
            -AssignmentCategory 'PIMEligible' `
            -AssignmentState 'Eligible' `
            -Notes ''
    }
    Write-Host "`r  Done: $total eligible schedules processed.       "
} catch {
    Write-Warning "Section B skipped — could not retrieve PIM eligibility schedules: $_"
}

# ── C. Entra PIM Active Schedules ────────────────────────────────────────────

Write-Host "Section C: Entra PIM — active role assignment schedules..."
try {
    $activeSchedules = Get-MgRoleManagementDirectoryRoleAssignmentScheduleInstance -All
    $filteredActive = $activeSchedules | Where-Object { $hpRoleIds.ContainsKey($_.RoleDefinitionId) }
    $total = @($filteredActive).Count; $i = 0
    foreach ($s in $filteredActive) {
        Write-Host "`r  Processing $((++$i)) / $total ..." -NoNewline
        Resolve-PrincipalAndAddRows -Rows $rows `
            -PrincipalId $s.PrincipalId `
            -ControlPlane 'EntraDirectoryRole' `
            -RoleName $hpRoleIds[$s.RoleDefinitionId] `
            -RoleDefinitionId $s.RoleDefinitionId `
            -Scope $(if ($s.DirectoryScopeId) { $s.DirectoryScopeId } else { '/' }) `
            -AssignmentCategory 'PIMActiveSchedule' `
            -AssignmentState 'ScheduledActive' `
            -Notes ''
    }
    Write-Host "`r  Done: $total active schedules processed.       "
} catch {
    Write-Warning "Section C skipped — could not retrieve PIM active schedules: $_"
}

# ── D. Azure RBAC Role Assignments ───────────────────────────────────────────

Write-Host "Section D: Azure RBAC — role assignments..."
$rbacAssignments = @()

# Management groups
try {
    $mgGroups = Get-AzManagementGroup -ErrorAction Stop
    foreach ($mg in $mgGroups) {
        $scope = "/providers/Microsoft.Management/managementGroups/$($mg.Name)"
        $rbacAssignments += Get-AzRoleAssignment -Scope $scope -ErrorAction SilentlyContinue |
            Where-Object { $_.RoleDefinitionName -in $AzureRBACHighlyPrivilegedRoles }
    }
} catch {
    Write-Warning "Could not enumerate management groups: $_"
}

# Subscriptions
$subscriptions = Get-AzSubscription -ErrorAction SilentlyContinue
foreach ($sub in $subscriptions) {
    $scope = "/subscriptions/$($sub.Id)"
    $rbacAssignments += Get-AzRoleAssignment -Scope $scope -ErrorAction SilentlyContinue |
        Where-Object { $_.RoleDefinitionName -in $AzureRBACHighlyPrivilegedRoles }
}

# Deduplicate by RoleAssignmentId before expansion
$rbacAssignments = $rbacAssignments | Sort-Object -Property RoleAssignmentId -Unique

$total = $rbacAssignments.Count; $i = 0
foreach ($ra in $rbacAssignments) {
    Write-Host "`r  Processing $((++$i)) / $total ..." -NoNewline
    $principalId = $ra.ObjectId
    $principalType = $ra.ObjectType

    if ($principalType -eq 'User') {
        $user = Get-CachedUser -Id $principalId
        $rows.Add((New-ReportRow `
            -ControlPlane 'AzureRBAC' `
            -RoleName $ra.RoleDefinitionName `
            -RoleDefinitionId $ra.RoleDefinitionId `
            -Scope $ra.Scope `
            -AssignmentCategory 'DirectAssignment' `
            -AssignmentState 'Active' `
            -PrincipalType 'User' `
            -EffectiveUserId $(if ($user.Id) { $user.Id } else { $principalId }) `
            -EffectiveUserUPN $(if ($user.UserPrincipalName) { $user.UserPrincipalName } else { '' }) `
            -EffectiveUserDisplayName $(if ($user.DisplayName) { $user.DisplayName } else { $ra.DisplayName }) `
            -SourceGroupId '' -SourceGroupDisplayName '' -IsRoleAssignableGroup '' -Notes ''))
    }
    elseif ($principalType -eq 'Group') {
        $group = Get-CachedGroup -Id $principalId
        $groupName = if ($group.DisplayName) { $group.DisplayName } else { $ra.DisplayName }
        $isRAG = if ($group -and $group.IsAssignableToRole) { 'Yes' } else { 'No' }
        $members = if ($group) { Get-CachedGroupMembers -GroupId $group.Id } else { @() }

        if ($members.Count -eq 0) {
            $rows.Add((New-ReportRow `
                -ControlPlane 'AzureRBAC' -RoleName $ra.RoleDefinitionName `
                -RoleDefinitionId $ra.RoleDefinitionId -Scope $ra.Scope `
                -AssignmentCategory 'GroupAssignmentExpanded' -AssignmentState 'Active' `
                -PrincipalType 'Group (empty)' -EffectiveUserId '' -EffectiveUserUPN '' `
                -EffectiveUserDisplayName '' -SourceGroupId $principalId `
                -SourceGroupDisplayName $groupName -IsRoleAssignableGroup $isRAG `
                -Notes 'Group has no transitive user members'))
        } else {
            foreach ($m in $members) {
                $rows.Add((New-ReportRow `
                    -ControlPlane 'AzureRBAC' -RoleName $ra.RoleDefinitionName `
                    -RoleDefinitionId $ra.RoleDefinitionId -Scope $ra.Scope `
                    -AssignmentCategory 'GroupAssignmentExpanded' -AssignmentState 'Active' `
                    -PrincipalType 'User' -EffectiveUserId $m.Id `
                    -EffectiveUserUPN $m.UserPrincipalName -EffectiveUserDisplayName $m.DisplayName `
                    -SourceGroupId $principalId -SourceGroupDisplayName $groupName `
                    -IsRoleAssignableGroup $isRAG -Notes ''))
            }
        }
    }
    elseif ($principalType -eq 'ServicePrincipal') {
        $rows.Add((New-ReportRow `
            -ControlPlane 'AzureRBAC' -RoleName $ra.RoleDefinitionName `
            -RoleDefinitionId $ra.RoleDefinitionId -Scope $ra.Scope `
            -AssignmentCategory 'DirectAssignment' -AssignmentState 'Active' `
            -PrincipalType 'ServicePrincipal' -EffectiveUserId $principalId `
            -EffectiveUserUPN '' -EffectiveUserDisplayName $(if ($ra.DisplayName) { $ra.DisplayName } else { '' }) `
            -SourceGroupId '' -SourceGroupDisplayName '' -IsRoleAssignableGroup '' `
            -Notes ''))
    }
    else {
        $rows.Add((New-ReportRow `
            -ControlPlane 'AzureRBAC' -RoleName $ra.RoleDefinitionName `
            -RoleDefinitionId $ra.RoleDefinitionId -Scope $ra.Scope `
            -AssignmentCategory 'DirectAssignment' -AssignmentState 'Active' `
            -PrincipalType $principalType -EffectiveUserId $principalId `
            -EffectiveUserUPN '' -EffectiveUserDisplayName $(if ($ra.DisplayName) { $ra.DisplayName } else { '' }) `
            -SourceGroupId '' -SourceGroupDisplayName '' -IsRoleAssignableGroup '' `
            -Notes "Unknown principal type: $principalType"))
    }
}
Write-Host "`r  Done: $total RBAC assignments processed.       "

# ── E. Azure RBAC PIM (graceful) ─────────────────────────────────────────────

Write-Host "Section E: Azure RBAC PIM — eligible & scheduled-active..."

# Helper to process RBAC PIM schedule objects
function Process-RbacPimSchedules {
    param(
        [System.Collections.Generic.List[object]]$Rows,
        [array]$Schedules,
        [string]$AssignmentCategory,
        [string]$AssignmentState,
        [string]$Label
    )
    $filtered = $Schedules | Where-Object { $_.RoleDefinitionDisplayName -in $AzureRBACHighlyPrivilegedRoles }
    $total = @($filtered).Count; $i = 0
    foreach ($s in $filtered) {
        Write-Host "`r  ($Label) Processing $((++$i)) / $total ..." -NoNewline
        $principalId = $s.PrincipalId
        Resolve-PrincipalAndAddRows -Rows $Rows `
            -PrincipalId $principalId `
            -ControlPlane 'AzureRBAC' `
            -RoleName $s.RoleDefinitionDisplayName `
            -RoleDefinitionId $s.RoleDefinitionId `
            -Scope $s.Scope `
            -AssignmentCategory $AssignmentCategory `
            -AssignmentState $AssignmentState `
            -Notes ''
    }
    Write-Host "`r  ($Label) Done: $total schedules processed.       "
}

$pimAvailable = $true

# E.1 — Eligible
try {
    $rbacEligSchedules = @()
    foreach ($sub in $subscriptions) {
        $scope = "/subscriptions/$($sub.Id)"
        $rbacEligSchedules += Get-AzRoleEligibilityScheduleInstance -Scope $scope -ErrorAction Stop
    }
    Process-RbacPimSchedules -Rows $rows -Schedules $rbacEligSchedules `
        -AssignmentCategory 'PIMEligible' -AssignmentState 'Eligible' -Label 'Eligible'
} catch {
    Write-Warning "Section E (eligible) skipped — Get-AzRoleEligibilityScheduleInstance not available or errored: $_"
    $pimAvailable = $false
}

# E.2 — Scheduled-active
try {
    $rbacActiveSchedules = @()
    foreach ($sub in $subscriptions) {
        $scope = "/subscriptions/$($sub.Id)"
        $rbacActiveSchedules += Get-AzRoleAssignmentScheduleInstance -Scope $scope -ErrorAction Stop
    }
    Process-RbacPimSchedules -Rows $rows -Schedules $rbacActiveSchedules `
        -AssignmentCategory 'PIMActiveSchedule' -AssignmentState 'ScheduledActive' -Label 'ScheduledActive'
} catch {
    Write-Warning "Section E (scheduled-active) skipped — Get-AzRoleAssignmentScheduleInstance not available or errored: $_"
    $pimAvailable = $false
}

if (-not $pimAvailable) {
    Write-Warning "Some Azure RBAC PIM data was unavailable. Ensure the Az.Resources module supports PIM cmdlets and you have adequate permissions."
}

# ─────────────────────────────────────────────────────────────────────────────
# 6. DEDUPLICATION
# ─────────────────────────────────────────────────────────────────────────────

Write-Host "`nDeduplicating rows..."
$beforeCount = $rows.Count

$deduped = $rows |
    Sort-Object ControlPlane, RoleName, Scope, AssignmentCategory, AssignmentState, EffectiveUserId, SourceGroupId -Unique

$rows = [System.Collections.Generic.List[object]]::new()
$rows.AddRange(@($deduped))

Write-Host "  Before: $beforeCount  After: $($rows.Count)  Removed: $($beforeCount - $rows.Count)"

# ─────────────────────────────────────────────────────────────────────────────
# 7. EXPORT + SUMMARY
# ─────────────────────────────────────────────────────────────────────────────

$outPath = Join-Path $PSScriptRoot "HPA_Master_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
$rows | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $outPath

$uniqueUsers = ($rows | Where-Object { $_.PrincipalType -eq 'User' } |
    Select-Object -ExpandProperty EffectiveUserId -Unique).Count
$uniqueRoles = ($rows | Select-Object -ExpandProperty RoleName -Unique).Count

Write-Host "`n════════════════════════════════════════════════"
Write-Host "  HPA Master Report Complete"
Write-Host "  Total rows       : $($rows.Count)"
Write-Host "  Unique users     : $uniqueUsers"
Write-Host "  Unique roles     : $uniqueRoles"
Write-Host "  Exported to      : $outPath"
Write-Host "════════════════════════════════════════════════"
