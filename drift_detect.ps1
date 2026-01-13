<#
.SYNOPSIS
    Detects RBAC drift between Azure and Terraform state for one or more subscriptions.

.DESCRIPTION
    This script compares Azure role assignments against Terraform state to identify
    role assignments that exist in Azure but are not managed by Terraform.

.PARAMETER SubscriptionFolders
    One or more subscription folder names under ./subscriptions/ to check.
    If not specified, checks all subscription folders.

.PARAMETER OutputMarkdown
    If specified, outputs a markdown report file for each subscription with drift.
    Used by GitHub Actions to generate issue content.

.PARAMETER CI
    If specified, sets GitHub Actions output variables and uses CI-friendly output.

.EXAMPLE
    ./drift_detect.ps1
    # Checks all subscriptions locally

.EXAMPLE
    ./drift_detect.ps1 -SubscriptionFolders "my_subscription_1", "my_subscription_2"
    # Checks specific subscriptions

.EXAMPLE
    ./drift_detect.ps1 -SubscriptionFolders "my_subscription" -OutputMarkdown -CI
    # Runs in GitHub Actions mode with markdown output
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string[]]$SubscriptionFolders,

    [Parameter(Mandatory = $false)]
    [switch]$OutputMarkdown,

    [Parameter(Mandatory = $false)]
    [switch]$CI
)

$subscriptionsPath = Join-Path -Path $PSScriptRoot -ChildPath "subscriptions"

# Discover subscription folders if not specified
if (-not $SubscriptionFolders) {
    $SubscriptionFolders = Get-ChildItem -Path $subscriptionsPath -Directory | Select-Object -ExpandProperty Name
}

if ($SubscriptionFolders.Count -eq 0) {
    Write-Host "❌ No subscription folders found in ./subscriptions/" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "╔═══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║           RBAC Drift Detection                                ║" -ForegroundColor Cyan
Write-Host "╚═══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

$allDrift = @()

foreach ($folder in $SubscriptionFolders) {
    $folderPath = Join-Path -Path $subscriptionsPath -ChildPath $folder
    
    if (-not (Test-Path $folderPath)) {
        Write-Host "⚠️ Folder not found: $folder" -ForegroundColor Yellow
        continue
    }

    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor DarkGray
    Write-Host "🔍 Checking: $folder" -ForegroundColor Cyan
    
    Push-Location $folderPath
    try {
        # Read subscription ID from main.tf or backend config
        $mainTf = Get-Content -Path "main.tf" -Raw -ErrorAction SilentlyContinue
        if ($mainTf -match 'subscription_id\s*=\s*"([^"]+)"') {
            $subscriptionId = $matches[1]
        }
        else {
            Write-Host "   ❌ Could not find subscription_id in main.tf" -ForegroundColor Red
            continue
        }

        Write-Host "   Subscription ID: $subscriptionId" -ForegroundColor Gray

        # Set Azure context using Az PowerShell module
        $context = Set-AzContext -SubscriptionId $subscriptionId -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
        if (-not $context) {
            Write-Host "   ❌ Failed to set subscription context. Run 'Connect-AzAccount' first." -ForegroundColor Red
            continue
        }

        # Get Azure role assignments using Az PowerShell module
        $allRoleAssignments = Get-AzRoleAssignment -Scope "/subscriptions/$subscriptionId" | 
            Where-Object { $_.Scope.Contains($subscriptionId) -and $_.Scope -ne "/" }

        # Exclude time-based role assignments (PIM) - only those with an EndDateTime
        $scheduledInstances = Get-AzRoleAssignmentScheduleInstance -Scope "/subscriptions/$subscriptionId" -ErrorAction SilentlyContinue | 
            Where-Object { $_.Scope.Contains($subscriptionId) -and $_.Scope -ne "/" -and $_.EndDateTime }
        
        if ($?) {
            $roleAssignments = $allRoleAssignments | Where-Object {
                $_.RoleAssignmentId -notin $scheduledInstances.OriginRoleAssignmentId
            }
        }
        else {
            $roleAssignments = $allRoleAssignments
        }

        # Get Terraform state
        $state = terraform state pull 2>$null | ConvertFrom-Json
        if ($LASTEXITCODE -ne 0) {
            Write-Host "   ❌ Failed to pull terraform state. Run 'terraform init' first." -ForegroundColor Red
            continue
        }

        # Build a hashtable of state role assignments with their conditions
        $stateRoleAssignments = @{}
        $stateResources = $state.resources | Where-Object { $_.type -eq "azurerm_role_assignment" }
        foreach ($resource in $stateResources) {
            foreach ($instance in $resource.instances) {
                $id = $instance.attributes.id.ToLower()
                $stateRoleAssignments[$id] = @{
                    condition = $instance.attributes.condition
                    conditionVersion = $instance.attributes.condition_version
                }
            }
        }

        $stateIds = $stateRoleAssignments.Keys

        # Find drift - role assignments not in state OR with mismatched conditions
        $driftedRoles = @()
        foreach ($role in $roleAssignments) {
            $roleId = $role.RoleAssignmentId.ToLower()
            
            if ($roleId -notin $stateIds) {
                # Role assignment doesn't exist in state at all
                $driftedRoles += [PSCustomObject]@{
                    Role = $role
                    DriftType = "Missing"
                }
            }
            else {
                # Role exists in state - check for condition mismatch
                $stateEntry = $stateRoleAssignments[$roleId]
                $azureCondition = if ($role.Condition) { $role.Condition.Trim() } else { $null }
                $stateCondition = if ($stateEntry.condition) { $stateEntry.condition.Trim() } else { $null }
                
                # Detect mismatch if conditions differ
                $conditionsDiffer = $azureCondition -ne $stateCondition
                
                # Only compare version if at least one side has a condition
                $versionsDiffer = $false
                if ($azureCondition -or $stateCondition) {
                    $azureVersion = if ($role.ConditionVersion) { $role.ConditionVersion } else { $null }
                    $stateVersion = if ($stateEntry.conditionVersion) { $stateEntry.conditionVersion } else { $null }
                    $versionsDiffer = $azureVersion -ne $stateVersion
                }
                
                if ($conditionsDiffer -or $versionsDiffer) {
                    $driftedRoles += [PSCustomObject]@{
                        Role = $role
                        DriftType = "ConditionMismatch"
                    }
                }
            }
        }

        if ($driftedRoles.Count -gt 0) {
            Write-Host "   ⚠️ Drift detected: $($driftedRoles.Count) role(s) with drift" -ForegroundColor Yellow
            
            foreach ($item in $driftedRoles) {
                $role = $item.Role
                $allDrift += [PSCustomObject]@{
                    Subscription       = $folder
                    PrincipalName      = if ($role.DisplayName) { $role.DisplayName } else { "N/A" }
                    PrincipalId        = $role.ObjectId
                    RoleDefinitionName = $role.RoleDefinitionName
                    Scope              = $role.Scope
                    AssignmentId       = $role.RoleAssignmentId
                    Condition          = if ($role.Condition) { $role.Condition } else { "" }
                    DriftType          = $item.DriftType
                }
            }

            # Generate markdown report if requested
            if ($OutputMarkdown) {
                $mdContent = @()
                $mdContent += "## Drift Summary"
                $mdContent += ""
                $mdContent += "| Principal Name | Principal ID | Role Name | Scope | Drift Type | Condition |"
                $mdContent += "|----------------|--------------|-----------|-------|------------|-----------|"
                
                foreach ($item in $driftedRoles) {
                    $role = $item.Role
                    $principalName = if ($role.DisplayName) { $role.DisplayName } else { "N/A" }
                    $principalId = $role.ObjectId
                    $roleName = $role.RoleDefinitionName
                    $scope = $role.Scope
                    $driftType = $item.DriftType
                    $condition = if ($role.Condition) { $role.Condition -replace '\|', '\|' -replace '\n', ' ' } else { "-" }
                    
                    $mdContent += "| $principalName | ``$principalId`` | $roleName | ``$scope`` | $driftType | ``$condition`` |"
                }
                
                # Add remediation instructions for missing role assignments only
                $missingRoles = $driftedRoles | Where-Object { $_.DriftType -eq "Missing" }
                if ($missingRoles.Count -gt 0) {
                    $mdContent += ""
                    $mdContent += "---"
                    $mdContent += ""
                    $mdContent += "## Remediation Instructions"
                    $mdContent += ""
                    $mdContent += "To import the missing role assignments into Terraform, follow these steps:"
                    $mdContent += ""
                    
                    # Get current max index from tfvars
                    $tfvarsPath = Join-Path $folderPath "terraform.tfvars.json"
                    $currentTfvars = Get-Content $tfvarsPath -Raw | ConvertFrom-Json
                    $maxIndex = ($currentTfvars.permissions.PSObject.Properties.Name | ForEach-Object { [int]$_ } | Measure-Object -Maximum).Maximum
                    if ($null -eq $maxIndex) { $maxIndex = -1 }
                    
                    $mdContent += "### 1. Add to ``import.tf``"
                    $mdContent += ""
                    $mdContent += "``````hcl"
                    
                    $importIndex = $maxIndex + 1
                    foreach ($item in $missingRoles) {
                        $role = $item.Role
                        $mdContent += "import {"
                        $mdContent += "  to = module.rbac.azurerm_role_assignment.basic[`"$importIndex`"]"
                        $mdContent += "  id = `"$($role.RoleAssignmentId)`""
                        $mdContent += "}"
                        $mdContent += ""
                        $importIndex++
                    }
                    $mdContent += "``````"
                    $mdContent += ""
                    
                    $mdContent += "### 2. Add to ``terraform.tfvars.json``"
                    $mdContent += ""
                    $mdContent += "Add the following entries to the ``permissions`` object:"
                    $mdContent += ""
                    $mdContent += "``````json"
                    
                    $varIndex = $maxIndex + 1
                    foreach ($item in $missingRoles) {
                        $role = $item.Role
                        $entry = [ordered]@{
                            roleDefinitionName = $role.RoleDefinitionName
                            scope = $role.Scope
                            principalId = $role.ObjectId
                        }
                        if ($role.Condition) {
                            $entry.condition = $role.Condition
                            $entry.conditionVersion = $role.ConditionVersion
                        }
                        $jsonEntry = $entry | ConvertTo-Json -Depth 10
                        # Indent the JSON for readability
                        $indentedJson = $jsonEntry -split "`n" | ForEach-Object { "  $_" }
                        $mdContent += "`"$varIndex`": {"
                        $mdContent += ($indentedJson | Select-Object -Skip 1 | Select-Object -SkipLast 1)
                        $mdContent += "  },"
                        $varIndex++
                    }
                    $mdContent += "``````"
                    $mdContent += ""
                    $mdContent += "### 3. Commit and Create PR"
                    $mdContent += ""
                    $mdContent += "``````bash"
                    $mdContent += "git add ."
                    $mdContent += "git commit -m `"Import missing role assignments`""
                    $mdContent += "git push"
                    $mdContent += "``````"
                    $mdContent += ""
                    $mdContent += "Then create a Pull Request to trigger the Terraform plan workflow."
                }
                
                $mdContent -join "`n" | Set-Content -Path (Join-Path $folderPath "drift_report.md")
            }
        }
        else {
            Write-Host "   ✅ No drift detected" -ForegroundColor Green
        }
    }
    finally {
        Pop-Location
    }
}

# Summary
Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor DarkGray
Write-Host ""

if ($allDrift.Count -gt 0) {
    Write-Host "📊 Drift Summary: $($allDrift.Count) role assignment(s) with drift found" -ForegroundColor Yellow
    Write-Host ""
    
    $allDrift | Group-Object -Property Subscription | ForEach-Object {
        Write-Host "📁 $($_.Name): $($_.Count) role(s)" -ForegroundColor Yellow
        $_.Group | Format-Table -Property PrincipalName, RoleDefinitionName, Scope, DriftType -AutoSize
    }
    
    # Export to CSV (local runs)
    if (-not $CI) {
        $csvPath = Join-Path -Path $PSScriptRoot -ChildPath "drift_report.csv"
        $allDrift | Export-Csv -Path $csvPath -NoTypeInformation
        Write-Host "📄 Full report exported to: drift_report.csv" -ForegroundColor Cyan
    }

    # Set GitHub Actions output
    if ($CI) {
        Write-Output "drift_found=true" >> $env:GITHUB_OUTPUT
        Write-Output "::warning::RBAC Drift detected! $($allDrift.Count) role(s) not in Terraform state."
    }
}
else {
    Write-Host "✅ No drift detected across all subscriptions!" -ForegroundColor Green
    
    if ($CI) {
        Write-Output "drift_found=false" >> $env:GITHUB_OUTPUT
    }
}

Write-Host ""