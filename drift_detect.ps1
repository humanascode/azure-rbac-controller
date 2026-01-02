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

        # Set Azure context
        az account set -s $subscriptionId 2>$null
        if ($LASTEXITCODE -ne 0) {
            Write-Host "   ❌ Failed to set subscription context. Run 'az login' first." -ForegroundColor Red
            continue
        }

        # Get Azure role assignments
        $roleAssignments = az role assignment list --all 2>$null | ConvertFrom-Json
        if ($LASTEXITCODE -ne 0) {
            Write-Host "   ❌ Failed to list role assignments" -ForegroundColor Red
            continue
        }
        $roleAssignments = $roleAssignments | Where-Object { $_.scope.ToLower().Contains($subscriptionId.ToLower()) }

        # Get Terraform state
        $state = terraform state pull 2>$null | ConvertFrom-Json
        if ($LASTEXITCODE -ne 0) {
            Write-Host "   ❌ Failed to pull terraform state. Run 'terraform init' first." -ForegroundColor Red
            continue
        }

        $stateIds = @(($state.resources | Where-Object { $_.type -eq "azurerm_role_assignment" }).instances.attributes.id) | 
            ForEach-Object { $_.ToLower() }

        # Find drift
        $driftedRoles = $roleAssignments | Where-Object { $_.id.ToLower() -notin $stateIds }

        if ($driftedRoles.Count -gt 0) {
            Write-Host "   ⚠️ Drift detected: $($driftedRoles.Count) role(s) not in Terraform state" -ForegroundColor Yellow
            
            foreach ($role in $driftedRoles) {
                $allDrift += [PSCustomObject]@{
                    Subscription       = $folder
                    PrincipalName      = if ($role.principalName) { $role.principalName } else { "N/A" }
                    PrincipalId        = $role.principalId
                    RoleDefinitionName = $role.roleDefinitionName
                    Scope              = $role.scope
                    AssignmentId       = $role.id
                }
            }

            # Generate markdown report if requested
            if ($OutputMarkdown) {
                $mdTable = @()
                $mdTable += "| Principal Name | Principal ID | Role Name | Role Definition ID | Assignment ID | Scope |"
                $mdTable += "|----------------|--------------|-----------|-------------------|---------------|-------|"
                
                foreach ($role in $driftedRoles) {
                    $principalName = if ($role.principalName) { $role.principalName } else { "N/A" }
                    $principalId = $role.principalId
                    $roleName = $role.roleDefinitionName
                    $roleDefId = ($role.roleDefinitionId -split '/')[-1]
                    $assignmentId = ($role.id -split '/')[-1]
                    $scope = $role.scope
                    
                    $mdTable += "| $principalName | ``$principalId`` | $roleName | ``$roleDefId`` | ``$assignmentId`` | ``$scope`` |"
                }
                
                $mdTable -join "`n" | Set-Content -Path (Join-Path $folderPath "drift_report.md")
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
    Write-Host "📊 Drift Summary: $($allDrift.Count) unmanaged role assignment(s) found" -ForegroundColor Yellow
    Write-Host ""
    
    $allDrift | Group-Object -Property Subscription | ForEach-Object {
        Write-Host "📁 $($_.Name): $($_.Count) role(s)" -ForegroundColor Yellow
        $_.Group | Format-Table -Property PrincipalName, RoleDefinitionName, Scope -AutoSize
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