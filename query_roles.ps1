# Entra Directory Roles → Effective assignments (Direct or Group expanded)
# Exports: Entra_ID_Directory_Roles.csv
# You must Connect-MgGraph once before running this script.

$ctx = Get-MgContext
if (-not $ctx) { throw "Not connected to Microsoft Graph. Run Connect-MgGraph first." }

# Role ID → Name lookup
$roleNames = @{}
Get-MgRoleManagementDirectoryRoleDefinition -All | ForEach-Object { $roleNames[$_.Id] = $_.DisplayName }

$assignments = Get-MgRoleManagementDirectoryRoleAssignment -All
$rows = [System.Collections.Generic.List[object]]::new()

$i = 0
foreach ($a in $assignments) {
    Write-Host "`rProcessing assignment $((++$i)) of $($assignments.Count)..." -NoNewline
    $roleName = $roleNames[$a.RoleDefinitionId]
    $base = @{ RoleName = $roleName; RoleSystem = "Entra Directory"; ScopeLevel = "Tenant"; Notes = "" }

    # Try user
    $u = try { Get-MgUser -UserId $a.PrincipalId -ErrorAction Stop } catch { $null }
    if ($u) {
        $rows.Add([pscustomobject]($base + @{
            UserPrincipalName = $u.UserPrincipalName; DisplayName = $u.DisplayName
            AssignmentType = "Direct"; AssignmentPath = "Direct"; RequiresGroupExpansion = "No"
        }))
        continue
    }

    # Try group → expand transitive user members
    $g = try { Get-MgGroup -GroupId $a.PrincipalId -ErrorAction Stop } catch { $null }
    if ($g) {
        Get-MgGroupTransitiveMember -GroupId $g.Id -All |
          Where-Object { $_.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.user' } |
          ForEach-Object {
            $rows.Add([pscustomobject]($base + @{
                UserPrincipalName = $_.AdditionalProperties.userPrincipalName
                DisplayName       = $_.AdditionalProperties.displayName
                AssignmentType    = "Effective (via group)"
                AssignmentPath    = "Group: $($g.DisplayName) (transitive)"
                RequiresGroupExpansion = "Yes"
            }))
          }
        continue
    }

    # Non-user principal (service principal, etc.)
    $rows.Add([pscustomobject]($base + @{
        UserPrincipalName = ""; DisplayName = ""
        AssignmentType = "Non-User Principal"; AssignmentPath = "PrincipalId: $($a.PrincipalId)"
        RequiresGroupExpansion = "N/A"; Notes = "Principal is not a user/group (likely service principal)."
    }))
}

Write-Host ""
$rows | Sort-Object UserPrincipalName, RoleName, AssignmentPath -Unique |
  Export-Csv -NoTypeInformation -Encoding UTF8 -Path ".\Entra_ID_Directory_Roles.csv"

Write-Host "Exported: .\Entra_ID_Directory_Roles.csv"
Write-Host "Connected account: $($ctx.Account)  Tenant: $($ctx.TenantId)"
