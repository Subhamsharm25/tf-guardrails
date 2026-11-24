# Intentionally misconfigured Azure resources. The azurerm provider must authenticate even to
# plan, so CI validates this file and evaluates plan.fixture.json, which mirrors it.

terraform {
  required_providers {
    azurerm = { source = "hashicorp/azurerm", version = "~> 4.14" }
  }
}

provider "azurerm" {
  features {}
}

resource "azurerm_resource_group" "app" { # TAG-001
  name     = "rg-noncompliant"
  location = "centralindia"
}

resource "azurerm_storage_account" "data" { # AZ-ST-001, TAG-001
  name                            = "noncompliantdata01"
  resource_group_name             = azurerm_resource_group.app.name
  location                        = azurerm_resource_group.app.location
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  min_tls_version                 = "TLS1_0"
  https_traffic_only_enabled      = false
  allow_nested_items_to_be_public = true
}

resource "azurerm_network_security_group" "web" { # AZ-NSG-001, TAG-001
  name                = "nsg-web"
  location            = azurerm_resource_group.app.location
  resource_group_name = azurerm_resource_group.app.name

  security_rule {
    name                       = "allow-rdp"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "3389"
    source_address_prefix      = "Internet"
    destination_address_prefix = "*"
  }
}
