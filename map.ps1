<#
.SYNOPSIS
    Maps Azure RBAC role assignments for one or more subscriptions and generates Terraform configuration.

.DESCRIPTION
    This script:
    - Accepts one or more Azure subscription IDs
    - Creates a folder structure under ./subscriptions/<subscription_name>/
    - Scans existing RBAC role assignments
    - Generates Terraform files (main.tf, import.tf, terraform.tfvars.json, backend.tf)

    Note: Service principal and GitHub secrets must be configured manually.
    See README.md for setup instructions.

.PARAMETER SubscriptionIds
    One or more Azure subscription IDs to process.

.PARAMETER StorageAccountName
    Azure Storage Account name for Terraform backend state. (Required)

.PARAMETER StorageAccountResourceGroup
    Resource group containing the storage account. (Required)

.PARAMETER StorageAccountContainer
    Blob container name for state files (default: "tfstate").

.EXAMPLE
    ./map.ps1 -SubscriptionIds "sub-id-1", "sub-id-2" -StorageAccountName "tfstate123" -StorageAccountResourceGroup "rg-tfstate"

.EXAMPLE
    ./map.ps1 -SubscriptionIds "sub-id-1" -StorageAccountName "tfstate123" -StorageAccountResourceGroup "rg-tfstate" -StorageAccountContainer "mycontainer"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string[]]$SubscriptionIds,

    [Parameter(Mandatory = $true)]
    [string]$StorageAccountName,

    [Parameter(Mandatory = $true)]
    [string]$StorageAccountResourceGroup,

    [Parameter(Mandatory = $false)]
    [string]$StorageAccountContainer = "tfstate"
)

#region Helper Functions

function Get-SubscriptionFolderName {
    param([string]$SubscriptionId)
    
    $sub = Get-AzSubscription -SubscriptionId $SubscriptionId -ErrorAction SilentlyContinue
    if ($sub) {
        # Sanitize subscription name for folder (remove special chars, replace spaces)
        $name = $sub.Name -replace '[^\w\-]', '_' -replace '__+', '_'
        return $name.ToLower()
    }
    return $SubscriptionId
}

function New-SubscriptionFolder {
    param([string]$FolderName)
    
    $path = Join-Path -Path $PSScriptRoot -ChildPath "subscriptions/$FolderName"
    if (-not (Test-Path $path)) {
        New-Item -ItemType Directory -Path $path -Force | Out-Null
        Write-Host "✅ Created folder: subscriptions/$FolderName" -ForegroundColor Green
    }
    else {
        Write-Host "📁 Folder exists: subscriptions/$FolderName" -ForegroundColor Yellow
    }
    return $path
}

function Get-RoleAssignmentsForSubscription {
    param([string]$SubscriptionId)
    
    Write-Host "🔍 Scanning role assignments for subscription: $SubscriptionId" -ForegroundColor Cyan
    
    Set-AzContext -SubscriptionId $SubscriptionId | Out-Null
    $allRoleAssignments = Get-AzRoleAssignment -Scope "/subscriptions/$SubscriptionId" | 
        Where-Object { $_.Scope.Contains($SubscriptionId) -and $_.Scope -ne "/" }

    # Exclude time-based role assignments (PIM) - only those with an EndDateTime
    $scheduledInstances = Get-AzRoleAssignmentScheduleInstance -Scope "/subscriptions/$SubscriptionId" -ErrorAction SilentlyContinue | 
        Where-Object { $_.Scope.Contains($SubscriptionId) -and $_.Scope -ne "/" -and $_.EndDateTime }
    
    if ($?) {
        $roleAssignments = $allRoleAssignments | Where-Object {
            $_.RoleAssignmentId -notin $scheduledInstances.OriginRoleAssignmentId
        }
    }
    else {
        $roleAssignments = $allRoleAssignments
    }

    
    Write-Host "   Found $($roleAssignments.Count) role assignments" -ForegroundColor Gray
    return $roleAssignments
}

function New-TerraformFiles {
    param(
        [string]$FolderPath,
        [string]$SubscriptionId,
        [string]$FolderName,
        [array]$RoleAssignments,
        [string]$StorageAccountName,
        [string]$StorageAccountResourceGroup,
        [string]$StorageAccountContainer
    )

    # Generate main.tf
    $mainTf = @"
terraform {
  required_version = ">= 1.6"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 4.0"
    }
  }
}

provider "azurerm" {
  features {}
  subscription_id = "$SubscriptionId"
  use_oidc        = true
}

variable "permissions" {
  type = map(object({
    roleDefinitionName = optional(string)
    roleDefinitionId   = optional(string)
    principalId        = string
    scope              = string
    condition          = optional(string)
    conditionVersion   = optional(string)
  }))
  validation {
    condition = alltrue([
      for k, v in var.permissions : (v.roleDefinitionName != null || v.roleDefinitionId != null)
    ])
    error_message = "Each permission must have either roleDefinitionName or roleDefinitionId specified."
  }
}

module "rbac" {
  source  = "Azure/avm-res-authorization-roleassignment/azurerm"
  version = "0.3.0"

  enable_telemetry = false
  role_assignments_azure_resource_manager = {
    for key, value in var.permissions : key => {
      principal_id         = value.principalId
      role_definition_name = value.roleDefinitionId == null ? value.roleDefinitionName : null
      role_definition_id   = value.roleDefinitionId != null ? value.roleDefinitionId : null
      scope                = value.scope
      condition            = value.condition
      condition_version    = value.conditionVersion
    }
  }
}
"@

    # Generate backend.tf
    $backendTf = @"
terraform {
  backend "azurerm" {
    resource_group_name  = "$StorageAccountResourceGroup"
    storage_account_name = "$StorageAccountName"
    container_name       = "$StorageAccountContainer"
    key                  = "$FolderName.tfstate"
    use_oidc             = true
    use_azuread_auth     = true
  }
}
"@
    $backendTf | Out-File -FilePath (Join-Path $FolderPath "backend.tf") -Force -Encoding utf8NoBOM
    Write-Host "   📄 Generated backend.tf" -ForegroundColor Gray

    # Generate terraform.tfvars.json
    $jsonRolesHash = [ordered]@{}
    $i = 0
    foreach ($roleAssignment in $RoleAssignments) {
        $entry = [ordered]@{
            roleDefinitionName = $roleAssignment.RoleDefinitionName
            scope              = $roleAssignment.Scope
            principalId        = $roleAssignment.ObjectId
        }
        if ($roleAssignment.Condition) {
            $entry.condition = $roleAssignment.Condition
            $entry.conditionVersion = $roleAssignment.ConditionVersion
        }
        $jsonRolesHash[[string]$i] = $entry
        $i++
    }
    $json = @{ permissions = $jsonRolesHash }
    $json | ConvertTo-Json -Depth 10 | Out-File -FilePath (Join-Path $FolderPath "terraform.tfvars.json") -Force -Encoding utf8NoBOM

    # Generate import.tf
    $importTf = ""
    $i = 0
    foreach ($roleAssignment in $RoleAssignments) {
        $importTarget = "module.rbac.azurerm_role_assignment.basic[`"$i`"]"
        $importTf += @"

import {
  to = $importTarget
  id = "$($roleAssignment.RoleAssignmentId)"
}
"@
        $i++
    }

    $mainTf | Out-File -FilePath (Join-Path $FolderPath "main.tf") -Force -Encoding utf8NoBOM
    $importTf | Out-File -FilePath (Join-Path $FolderPath "import.tf") -Force -Encoding utf8NoBOM

    Write-Host "   📄 Generated main.tf, import.tf, terraform.tfvars.json" -ForegroundColor Gray
}

#endregion

#region Main Script

Write-Host ""
Write-Host "╔═══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║           Azure RBAC Terraform Mapper                         ║" -ForegroundColor Cyan
Write-Host "╚═══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Validate Azure connection
try {
    $context = Get-AzContext
    if (-not $context) {
        Write-Host "🔄 Not logged in to Azure. Initiating login..." -ForegroundColor Yellow
        Connect-AzAccount -UseDeviceAuthentication
    }
    else {
        Write-Host "✅ Connected to Azure as: $($context.Account.Id)" -ForegroundColor Green
    }
}
catch {
    Write-Host "❌ Failed to connect to Azure: $_" -ForegroundColor Red
    exit 1
}

# Create subscriptions folder if it doesn't exist
$subscriptionsPath = Join-Path -Path $PSScriptRoot -ChildPath "subscriptions"
if (-not (Test-Path $subscriptionsPath)) {
    New-Item -ItemType Directory -Path $subscriptionsPath -Force | Out-Null
}

# Verify storage account for Terraform state
Write-Host ""
Write-Host "🗄️  Checking Terraform state storage..." -ForegroundColor Cyan

$storageAccount = Get-AzStorageAccount -ResourceGroupName $StorageAccountResourceGroup -Name $StorageAccountName -ErrorAction SilentlyContinue

if (-not $storageAccount) {
    Write-Host "   ❌ Storage account '$StorageAccountName' not found in resource group '$StorageAccountResourceGroup'" -ForegroundColor Red
    Write-Host ""
    Write-Host "   Please create the storage account first. Example:" -ForegroundColor Yellow
    Write-Host "   az storage account create -n $StorageAccountName -g $StorageAccountResourceGroup -l <location> --sku Standard_LRS" -ForegroundColor Gray
    Write-Host ""
    exit 1
}
else {
    Write-Host "   ✅ Storage account '$StorageAccountName' found" -ForegroundColor Green
}

# Check/create container
$storageContext = $storageAccount.Context
$container = Get-AzStorageContainer -Name $StorageAccountContainer -Context $storageContext -ErrorAction SilentlyContinue

if (-not $container) {
    Write-Host "   Creating container '$StorageAccountContainer'..." -ForegroundColor Gray
    New-AzStorageContainer -Name $StorageAccountContainer -Context $storageContext -Permission Off | Out-Null
    Write-Host "   ✅ Container created" -ForegroundColor Green
}
else {
    Write-Host "   ✅ Container '$StorageAccountContainer' found" -ForegroundColor Green
}

# Get storage account resource ID
$storageAccountId = $storageAccount.Id

# Process each subscription
$processedSubs = @()
foreach ($subscriptionId in $SubscriptionIds) {
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor DarkGray
    
    try {
        # Get folder name from subscription
        $folderName = Get-SubscriptionFolderName -SubscriptionId $subscriptionId
        
        # Create folder structure
        $folderPath = New-SubscriptionFolder -FolderName $folderName
        
        # Get role assignments
        $roleAssignments = Get-RoleAssignmentsForSubscription -SubscriptionId $subscriptionId
        
        # Generate Terraform files
        New-TerraformFiles `
            -FolderPath $folderPath `
            -SubscriptionId $subscriptionId `
            -FolderName $folderName `
            -RoleAssignments $roleAssignments `
            -StorageAccountName $StorageAccountName `
            -StorageAccountResourceGroup $StorageAccountResourceGroup `
            -StorageAccountContainer $StorageAccountContainer

        $processedSubs += @{
            SubscriptionId = $subscriptionId
            FolderName     = $folderName
            RoleCount      = $roleAssignments.Count
        }
    }
    catch {
        Write-Host "❌ Failed to process subscription $subscriptionId : $_" -ForegroundColor Red
    }
}

# Summary
Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor DarkGray
Write-Host ""
Write-Host "📊 Summary" -ForegroundColor Cyan
Write-Host ""

foreach ($sub in $processedSubs) {
    Write-Host "   ✅ $($sub.FolderName)" -ForegroundColor Green
    Write-Host "      Subscription: $($sub.SubscriptionId)" -ForegroundColor Gray
    Write-Host "      Role Assignments: $($sub.RoleCount)" -ForegroundColor Gray
}

Write-Host ""
Write-Host "📁 Generated folder structure:" -ForegroundColor Cyan
Write-Host "   subscriptions/" -ForegroundColor Gray
foreach ($sub in $processedSubs) {
    Write-Host "   ├── $($sub.FolderName)/" -ForegroundColor Gray
    Write-Host "   │   ├── main.tf" -ForegroundColor DarkGray
    Write-Host "   │   ├── backend.tf" -ForegroundColor DarkGray
    Write-Host "   │   ├── import.tf" -ForegroundColor DarkGray
    Write-Host "   │   └── terraform.tfvars.json" -ForegroundColor DarkGray
}

Write-Host ""
Write-Host "🚀 Next steps:" -ForegroundColor Yellow
Write-Host "   1. Make sure you have set up a service principal with OIDC for GitHub Actions (see README.md)" -ForegroundColor Gray
Write-Host "   2. Make sure GitHub secrets are configured for authentication" -ForegroundColor Gray
Write-Host "   3. Review generated Terraform files in ./subscriptions/<name>/" -ForegroundColor Gray
Write-Host "   4. Commit and push to GitHub to trigger the workflows" -ForegroundColor Gray
Write-Host ""

#endregion