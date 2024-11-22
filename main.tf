# Resource Group
resource "azurerm_resource_group" "rg" {
  name     = "wazuh-misp-rg"
  location = "East US"
}

data "azurerm_client_config" "current" {}

# Virtual Network and Subnet
resource "azurerm_virtual_network" "vnet" {
  name                = "wazuh-misp-vnet"
  address_space       = ["10.0.0.0/16"]
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
}

resource "azurerm_subnet" "subnet" {
  name                 = "wazuh-misp-subnet"
  resource_group_name  = azurerm_resource_group.rg.name
  virtual_network_name = azurerm_virtual_network.vnet.name
  address_prefixes     = ["10.0.1.0/24"]
}


# Create public IPs
resource "azurerm_public_ip" "wazuh_nic" {
  name                = "wazuhPublicIP"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  allocation_method   = "Dynamic"
}

resource "azurerm_public_ip" "misp_nic" {
  name                = "mispPublicIP"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  allocation_method   = "Dynamic"
}

resource "azurerm_public_ip" "server_nic" {
  name                = "wazuhAgentPublicIP"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name
  allocation_method   = "Dynamic"
}

# resource "azurerm_subnet" "subnet" {
#   name                 = "wazuh-misp-subnet"
#   resource_group_name  = azurerm_resource_group.rg.name
#   virtual_network_name = azurerm_virtual_network.vnet.name
#   address_prefixes     = ["10.0.2.0/24"]
# }
# Create Azure Firewall


# Network Security Group to Allow HTTP, HTTPS, and SSH
resource "azurerm_network_security_group" "nsg" {
  name                = "wazuh-misp-nsg"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name

  security_rule {
    name                       = "SSH"
    priority                   = 1001
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "HTTP"
    priority                   = 1002
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "80"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "HTTPS"
    priority                   = 1003
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "443"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

    security_rule {
    name                       = "Allow-HTTPS"
    priority                   = 1004
    direction                  = "Outbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "443"  # HTTPS
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}



resource "azurerm_network_security_group" "internal" {
  name                = "internal_vms"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name

}
# Network interface for Wazuh nic
resource "azurerm_network_interface" "wazuh_nic" {
  name                = "wazuh-nic"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name

  ip_configuration {
    name                          = "wazuh-ip-config"
    subnet_id                     = azurerm_subnet.subnet.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.wazuh_nic.id
  }
}

resource "azurerm_network_interface" "misp_nic" {
  name                = "misp-nic"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name

  ip_configuration {
    name                          = "misp-ip-config"
    subnet_id                     = azurerm_subnet.subnet.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.misp_nic.id
  }
}

resource "azurerm_network_interface" "server_nic" {
  name                = "server-nic"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name

  ip_configuration {
    name                          = "misp-ip-config"
    subnet_id                     = azurerm_subnet.subnet.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.server_nic.id
  }
}

resource "azurerm_network_interface_security_group_association" "misp_nic_nsg_association" {
  network_interface_id      = azurerm_network_interface.misp_nic.id
  network_security_group_id = azurerm_network_security_group.nsg.id
}

resource "azurerm_network_interface_security_group_association" "wazuh_nic_nsg_association" {
  network_interface_id      = azurerm_network_interface.wazuh_nic.id
  network_security_group_id = azurerm_network_security_group.nsg.id
}

locals {
  current_user_id = coalesce(var.msi_id, data.azurerm_client_config.current.object_id)
}

# Key Vault to store API keys securely
resource "azurerm_key_vault" "vault" {
  name                       = "wazuhmisp-kv"
  location                   = azurerm_resource_group.rg.location
  resource_group_name        = azurerm_resource_group.rg.name
  tenant_id                  = data.azurerm_client_config.current.tenant_id
  sku_name                   = "standard"
  soft_delete_retention_days = 7

  access_policy {
    tenant_id = data.azurerm_client_config.current.tenant_id
    object_id = local.current_user_id

    key_permissions    = var.key_permissions
    secret_permissions = var.secret_permissions
  }
}

resource "random_string" "azurerm_key_vault_key_name" {
  length  = 13
  lower   = true
  numeric = false
  special = false
  upper   = false
}
resource "azurerm_key_vault_key" "key" {
  name = coalesce(var.key_name, "key-${random_string.azurerm_key_vault_key_name.result}")

  key_vault_id = azurerm_key_vault.vault.id
  key_type     = var.key_type
  key_size     = var.key_size
  key_opts     = var.key_ops

  rotation_policy {
    automatic {
      time_before_expiry = "P30D"
    }

    expire_after         = "P90D"
    notify_before_expiry = "P29D"
  }
}

# Key Vault secret to store the MISP API key
resource "azurerm_key_vault_secret" "misp_api_key" {
  name         = "misp-api-key"
  value        = var.misp_api_key 
  key_vault_id = azurerm_key_vault.vault.id
}

# Ubuntu VM for MISP with Containerized MISP Setup
resource "azurerm_linux_virtual_machine" "misp_vm" {
  name                = "misp-vm"
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location
  size                = "Standard_DS1_v2"
  admin_username      = "azureuser"
  network_interface_ids = [azurerm_network_interface.misp_nic.id]
  disable_password_authentication = true

   admin_ssh_key {
    username   = "azureuser"
    public_key = azapi_resource_action.ssh_public_key_gen.output.publicKey
  }
  custom_data = base64encode(file("scripts/install_misp.sh"))

    os_disk {
    name = "MISP_vm"
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
    }
    source_image_reference {
        publisher = "Canonical"
        offer     = "0001-com-ubuntu-server-jammy"
        sku       = "22_04-lts"  # For Ubuntu 22.04, adjust if Ubuntu 24 is available
        version   = "latest"
    }
}

# Create an Ubuntu VM
resource "azurerm_linux_virtual_machine" "wazuh_server" {
  name                = "wazuh-server"
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location
  size                = "Standard_DS1_v2"
  admin_username      = "azureuser" 
  network_interface_ids = [azurerm_network_interface.server_nic.id]
  disable_password_authentication = true

  admin_ssh_key {
    username   = "azureuser"
    public_key = azapi_resource_action.ssh_public_key_gen.output.publicKey
  }
  
    custom_data = base64encode(file("scripts/install_wazuh_agent.sh"))

    os_disk {
    name = "Wazuh-Server"
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
    }
    source_image_reference {
        publisher = "Canonical"
        offer     = "0001-com-ubuntu-server-jammy"
        sku       = "22_04-lts"  # For Ubuntu 22.04, adjust if Ubuntu 24 is available
        version   = "latest"
    }
}

resource "azurerm_route_table" "misp_route_table" {
  name                = "misp-route-table"
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location

  route {
    name                   = "default-internet-route"
    address_prefix         = "0.0.0.0/0"
    next_hop_type          = "Internet"
  }
}

# Windows VM for Wazuh Agent
resource "azurerm_linux_virtual_machine" "wazuh_linux_vm" {
    name                = "wazuh-linux-vm"
    resource_group_name = azurerm_resource_group.rg.name
    location            = azurerm_resource_group.rg.location
    size                = "Standard_DS1_v2"
    admin_username      = "azureuser"
    network_interface_ids = [azurerm_network_interface.wazuh_nic.id]
    disable_password_authentication = true

   admin_ssh_key {
    username   = "azureuser"
    public_key = azapi_resource_action.ssh_public_key_gen.output.publicKey
  }

    custom_data = base64encode(file("scripts/install_wazuh_agent.sh"))
  
    os_disk {
        name = "LinuxVM"
        caching              = "ReadWrite"
        storage_account_type = "Standard_LRS"
    }
    source_image_reference {
        publisher = "Canonical"
        offer     = "0001-com-ubuntu-server-jammy"
        sku       = "22_04-lts"  # For Ubuntu 22.04, adjust if Ubuntu 24 is available
        version   = "latest"
    }
}

