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
  subscription_id = "8af1cae0-0e3c-4e1d-9c0c-5bf6d1e0a4c9"
  use_oidc        = true
}

variable "permissions" {
  type = map(object({
    roleDefinitionName = optional(string)
    roleDefinitionId   = optional(string)
    principalId        = string
    scope              = string
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
    }
  }
}
