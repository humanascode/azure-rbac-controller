terraform {
  backend "azurerm" {
    resource_group_name  = "rg-terraform-state"
    storage_account_name = "tfstatewe1878"
    container_name       = "tfstate"
    key                  = "hjemmeprosjekt.tfstate"
    use_oidc             = true
    use_azuread_auth     = true
  }
}
