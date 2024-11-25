# Resource Group
resource "azurerm_resource_group" "rg" {
  name     = "misp-wazuh-rg"
  location = "East US"
}

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
    name                       = "RDP"
    priority                   = 1000
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "3389"
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
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "443"  # HTTPS
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

 security_rule {
    name                       = "Allow-WinRM-HTTPS"
    priority                   = 1005
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "5986"
    source_address_prefix      = "*"  # Restrict to specific IP or range
    destination_address_prefix = "*"
  }

   security_rule {
    name                       = "Allow-WinRM-HTTP"
    priority                   = 1006
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "5985"
    source_address_prefix      = "*"  # Restrict to specific IP or range
    destination_address_prefix = "*"
  }
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

resource "azurerm_public_ip" "windows_nic" {
  name                = "windows_private_ip"
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

# Create Azure Firewall



# resource "azurerm_network_security_group" "internal" {
#   name                = "internal_vms"
#   location            = azurerm_resource_group.rg.location
#   resource_group_name = azurerm_resource_group.rg.name

# }
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

resource "azurerm_network_interface" "windows_nic" {
  name                = "windows-nic"
  location            = azurerm_resource_group.rg.location
  resource_group_name = azurerm_resource_group.rg.name

  ip_configuration {
    name                          = "windows-ip-config"
    subnet_id                     = azurerm_subnet.subnet.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.windows_nic.id
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

resource "azurerm_network_interface_security_group_association" "windows_nic_nsg_association" {
  network_interface_id      = azurerm_network_interface.windows_nic.id
  network_security_group_id = azurerm_network_security_group.nsg.id
}

resource "azurerm_network_interface_security_group_association" "wazuh_manager_nsg_association" {
  network_interface_id      = azurerm_network_interface.server_nic.id
  network_security_group_id = azurerm_network_security_group.nsg.id
}

locals {
  current_user_id = coalesce(var.msi_id, data.azurerm_client_config.current.object_id)
}

# Key Vault to store API keys securely
# resource "azurerm_key_vault" "vault" {
#   name                       = "wazuhmisp-kv"
#   location                   = azurerm_resource_group.rg.location
#   resource_group_name        = azurerm_resource_group.rg.name
#   tenant_id                  = data.azurerm_client_config.current.tenant_id
#   sku_name                   = "standard"
#   soft_delete_retention_days = 7

#   access_policy {
#     tenant_id = data.azurerm_client_config.current.tenant_id
#     object_id = local.current_user_id

#     key_permissions    = var.key_permissions
#     secret_permissions = var.secret_permissions
#   }
# }

# resource "random_string" "azurerm_key_vault_key_name" {
#   length  = 13
#   lower   = true
#   numeric = false
#   special = false
#   upper   = false
# }
# resource "azurerm_key_vault_key" "key" {
#   name = coalesce(var.key_name, "key-${random_string.azurerm_key_vault_key_name.result}")

#   key_vault_id = azurerm_key_vault.vault.id
#   key_type     = var.key_type
#   key_size     = var.key_size
#   key_opts     = var.key_ops

#   rotation_policy {
#     automatic {
#       time_before_expiry = "P30D"
#     }

#     expire_after         = "P90D"
#     notify_before_expiry = "P29D"
#   }
# }

# # Key Vault secret to store the MISP API key
# resource "azurerm_key_vault_secret" "misp_api_key" {
#   name         = "misp-api-key"
#   value        = var.misp_api_key 
#   key_vault_id = azurerm_key_vault.vault.id
# }

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
    public_key = file("~/.ssh/id_rsa.pub")
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
  depends_on = [azurerm_linux_virtual_machine.misp_vm] 
  name                = "wazuh-server"
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location
  size                = "Standard_D4s_v3"
  admin_username      = "azureuser" 
  network_interface_ids = [azurerm_network_interface.server_nic.id]
  disable_password_authentication = true

  admin_ssh_key {
    username   = "azureuser"
    public_key = file("~/.ssh/id_rsa.pub")
  }

    # custom_data = base64encode(file("scripts/install_wazuh_server.sh"))

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

output "wazuh_server_linux_ip" {
  value = azurerm_linux_virtual_machine.wazuh_server.private_ip_address
}

data "template_file" "wazuh_config" {
  template = file("scripts/wazuh_Server_conf_file.yml")

  vars = {
    wazuh_server_linux_ip = azurerm_linux_virtual_machine.wazuh_server.private_ip_address
  }
}


resource "null_resource" remoteExecProvisionerWFolder {
    depends_on = [ azurerm_linux_virtual_machine.wazuh_server]
    provisioner "file" {
    content      = data.template_file.wazuh_config.rendered  # Path to the local decoder file
    destination = "/tmp/config.yml"         # Destination path on the remote VM
    
      connection {
        type        = "ssh"
        user        = "azureuser"  # SSH username
        private_key = file("~/.ssh/id_rsa")  # Path to your SSH private key
        host        = azurerm_linux_virtual_machine.wazuh_server.public_ip_address  # Public IP of the VM
    }  
  }
     provisioner "remote-exec" {
      inline = [
        "cd /home/azureuser/",
        "curl -sO https://packages.wazuh.com/4.9/wazuh-install.sh",
        "curl -sO https://packages.wazuh.com/4.9/config.yml",
        "sudo chown -R azureuser:azureuser ./config.yml",
        "sudo rm -rf ./confil.yml",
        "sudo cp /tmp/config.yml ./",
        "sudo chown -R azureuser:azureuser ./config.yml",
        "sudo bash wazuh-install.sh --generate-config-files",
        "curl -sO https://packages.wazuh.com/4.9/wazuh-install.sh",
        "sudo bash wazuh-install.sh --wazuh-indexer node-1",
        "sudo bash wazuh-install.sh --start-cluster",
        # "sudo tar -axf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt -O | grep -P \"'admin'\"  -A 1",
        # "sudo grep -P \"'admin'\" /tmp/wazuh-install-files/wazuh-passwords.txt -A 1 | grep 'indexer_username' | sed \"s/.*indexer_username: //'\" -e 's/[\"\"]//g' > /tmp/indexer_username.txt",
        # "sudo grep -P \"'admin'\" /tmp/wazuh-install-files/wazuh-passwords.txt -A 1 | grep 'indexer_password' | sed \"s/.*indexer_password= //'\" -e 's/[\"\"]//g' > /tmp/indexer_password.txt",
        "sudo bash wazuh-install.sh --wazuh-server wazuh-1",
        "sudo bash wazuh-install.sh --wazuh-dashboard dashboard",
        "sudo tar -axf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt -O | grep -P \"'admin'\" -A 1 >> /tmp/required.txt"
        ]

      connection {
        type        = "ssh"
        user        = "azureuser"  # SSH username
        private_key = file("~/.ssh/id_rsa")  # Path to your SSH private key
        host        = azurerm_linux_virtual_machine.wazuh_server.public_ip_address  # Public IP of the VM
    }  
  }

  #  provisioner "local-exec" {
  #   command = <<EOT
  #     scp -i ~/.ssh/id_rsa azureuser@$(terraform output -raw server_linux_ip):/tmp/required.txt C:\Users\AirxP\Desktop\dev\dev.computersecuity_final_project\computersecurity\admin_credentials.txt
  #   EOT
  # } 
}


resource "null_resource" remoteExecProvisionerWFolder1 {
    depends_on = [ null_resource.remoteExecProvisionerWFolder ]
    # Provisioner to upload the custom decoder and restart Wazuh
    provisioner "file" {
    source      = "scripts/sysmonforlinux.xml"  # Path to the local decoder file
    destination = "/tmp/sysmonforlinux.xml"         # Destination path on the remote VM

    connection {
        type        = "ssh"
        user        = "azureuser"  # SSH username
        private_key = file("~/.ssh/id_rsa")  # Path to your SSH private key
        host        = azurerm_linux_virtual_machine.wazuh_server.public_ip_address  # Public IP of the VM
      }  
    }

    provisioner "remote-exec" {
      inline = [
      # Move the uploaded decoder to the correct Wazuh directory
      "sudo mv /tmp/sysmonforlinux.xml /var/ossec/etc/decoders/sysmonforlinux.xml",

      # Set proper permissions for the Wazuh decoder file
      "sudo chown wazuh:wazuh /var/ossec/etc/decoders/sysmonforlinux.xml",
      "sudo systemctl restart wazuh-manager"

      # Restart the Wazuh manager to apply the new decoder
    ]
    connection {
        type        = "ssh"
        user        = "azureuser"  # SSH username
        private_key = file("~/.ssh/id_rsa")  # Path to your SSH private key
        host        = azurerm_linux_virtual_machine.wazuh_server.public_ip_address  # Public IP of the VM
    }  
  }
}

resource "null_resource" remoteExecProvisionerWFolder2 {
    depends_on = [null_resource.remoteExecProvisionerWFolder1]
  # Upload the ossec.conf template
    provisioner "file" {
    source = "scripts/windows_wazuh_agent.py"  # Path to the template file
    destination = "/tmp/windows_wazuh_agent.py"  # Destination path on Wazuh Manager
    
    connection {
        type        = "ssh"
        user        = "azureuser"  # SSH username
        private_key = file("~/.ssh/id_rsa")  # Path to your SSH private key
        host        = azurerm_linux_virtual_machine.wazuh_server.public_ip_address  # Public IP of the VM
      }  
    }
     # Restart Wazuh to apply the changes
    provisioner "remote-exec" {
      inline = [
      "echo 'Copying py file to working dir'",
      "sudo cp /tmp/windows_wazuh_agent.py .",
      "sudo chown azureuser:azureuser windows_wazuh_agent.py",
      "sudo usermod -a -G root azureuser",
      "echo 'Copying file to /var/ossec/integrations...'",
      "sudo cp windows_wazuh_agent.py /var/ossec/integrations/",
      # "sudo cp /tmp/windows_wazuh_agent.py /var/ossec/integrations/",
      "echo 'Setting permissions on file...'",
      "sudo chmod 750 /var/ossec/integrations/windows_wazuh_agent.py",
      "echo 'Changing ownership of file...'",
      "sudo chown root:wazuh /var/ossec/integrations/windows_wazuh_agent.py",
      "sudo systemctl restart wazuh-manager"
    ]
    connection {
        type        = "ssh"
        user        = "azureuser"  # SSH username
        private_key = file("~/.ssh/id_rsa")  # Path to your SSH private key
        host        = azurerm_linux_virtual_machine.wazuh_server.public_ip_address  # Public IP of the VM
    }  
  }
}

resource "null_resource" remoteExecProvisionerWFolder3 {
    depends_on = [null_resource.remoteExecProvisionerWFolder2]
    provisioner "file" {
    source      = "scripts/misp.xml"  # Path to the local decoder file
    destination = "/tmp/misp.xml"         # Destination path on the remote VM

     connection {
      type        = "ssh"
      user        = "azureuser"  # SSH username
      private_key = file("~/.ssh/id_rsa")  # Path to your SSH private key
      host        = azurerm_linux_virtual_machine.wazuh_server.public_ip_address  # Public IP of the VM
    }
    }

       # Restart Wazuh to apply the changes
    provisioner "remote-exec" {
      inline = [
      "sudo cp /tmp/misp.xml /var/ossec/etc/rules/",
      # "sudo systemctl restart wazuh-manager",
      # Backup the existing ossec.conf
      "sudo cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.bak",

      # Append the integration block

       # Append the integration block right before the closing </ossec_config> tag

       #Append the integration block right before the closing </ossec_config> tag
      # "sudo sed -i 's#</ossec_config>#  <integration>\\n    <name>windows_wazuh_agent.py</name>\\n    <group>sysmon_event1,sysmon_event3,sysmon_event6,sysmon_event7,sysmon_event_15,sysmon_event_22,syscheck</group>\\n    <alert_format>json</alert_format>\\n  </integration>\\n</ossec_config>#' /var/ossec/etc/ossec.conf",

      "echo '<integration>' | sudo tee -a /var/ossec/etc/ossec.conf",
      "echo '  <name>windows_wazuh_agent.py</name>' | sudo tee -a /var/ossec/etc/ossec.conf",
      "echo '  <group>sysmon_event1,sysmon_event3,sysmon_event6,sysmon_event7,sysmon_event_15,sysmon_event_22,syscheck</group>' | sudo tee -a /var/ossec/etc/ossec.conf",
      "echo '  <alert_format>json</alert_format>' | sudo tee -a /var/ossec/etc/ossec.conf",
      "echo '</integration>' | sudo tee -a /var/ossec/etc/ossec.conf",
      #Optional: Verify the update (this will show the last 20 lines of ossec.conf)
      "sudo tail -n 20 /var/ossec/etc/ossec.conf",
      # Restart Wazuh Manager
      # "sudo systemctl restart wazuh-manager"
      ]
     connection {
        type        = "ssh"
        user        = "azureuser"  # SSH username
        private_key = file("~/.ssh/id_rsa")  # Path to your SSH private key
        host        = azurerm_linux_virtual_machine.wazuh_server.public_ip_address  # Public IP of the VM
      }  
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

data "template_file" "linux_wazuh_agent" {
  template = file("scripts/install_wazuh_agent.sh")

  vars = {
    wazuh_server_linux_ip = azurerm_linux_virtual_machine.wazuh_server.private_ip_address
  }
}

# Windows VM for Wazuh Agent
resource "azurerm_linux_virtual_machine" "wazuh_linux_vm" {
    depends_on = [null_resource.remoteExecProvisionerWFolder3]
    name                = "wazuh-linux-vm"
    resource_group_name = azurerm_resource_group.rg.name
    location            = azurerm_resource_group.rg.location
    size                = "Standard_DS1_v2"
    admin_username      = "azureuser"
    network_interface_ids = [azurerm_network_interface.wazuh_nic.id]
    disable_password_authentication = true

   admin_ssh_key {
    username   = "azureuser"
    public_key = file("~/.ssh/id_rsa.pub")
  }

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
resource "null_resource" remoteExecProvisionerWFolder4 {
    depends_on = [ azurerm_linux_virtual_machine.wazuh_linux_vm]
    provisioner "file" {
    content      = data.template_file.linux_wazuh_agent.rendered  # Path to the local decoder file
    destination = "/tmp/install_wazuh_agent.sh"         # Destination path on the remote VM
    
      connection {
        type        = "ssh"
        user        = "azureuser"  # SSH username
        private_key = file("~/.ssh/id_rsa")  # Path to your SSH private key
        host        = azurerm_linux_virtual_machine.wazuh_linux_vm.public_ip_address  # Public IP of the VM
    }  
  }
     provisioner "remote-exec" {
      inline = [
            # Configure Wazuh agent to connect to the Wazuh Manager
            "cp /tmp/install_wazuh_agent.sh .",
            "sudo chmod +x install_wazuh_agent.sh",
            "sudo ./install_wazuh_agent.sh"    
          ]
      connection {
        type        = "ssh"
        user        = "azureuser"  # SSH username
        private_key = file("~/.ssh/id_rsa")  # Path to your SSH private key
        host        = azurerm_linux_virtual_machine.wazuh_linux_vm.public_ip_address  # Public IP of the VM
      }
    }
}

data "template_file" "windows_wazuh_agent" {
  template = file("scripts/windows_agent_install.ps1")

  vars = {
    wazuh_server_linux_ip = azurerm_linux_virtual_machine.wazuh_server.private_ip_address
  }
}


resource "azurerm_windows_virtual_machine" "wazuh_windows_agent_vm" {
  depends_on = [azurerm_linux_virtual_machine.wazuh_linux_vm] 
  name                = "wazuh-windows-agent-vm"
  computer_name         = "windowsagent01"
  admin_username      = "azureuser"
  admin_password      = random_password.password.result
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location
  size                = "Standard_B1s"
  network_interface_ids = [azurerm_network_interface.windows_nic.id]

  os_disk {
    name                 = "myOsDisk"
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  source_image_reference {
    publisher = "microsoftwindowsdesktop"
    offer     = "windows-10"
    sku       = "win10-22h2-pro"
    version   = "latest"
  }
}
  
  resource "azurerm_virtual_machine_extension" "web_server_install" {
  name                       = "wazuh-windows-agent-vm"
  virtual_machine_id         = azurerm_windows_virtual_machine.wazuh_windows_agent_vm.id
  publisher                  = "Microsoft.Compute"
  type                       = "CustomScriptExtension"
  type_handler_version       = "1.10"
  auto_upgrade_minor_version = true

   settings = <<SETTINGS
    {
      "script": "./scripts/enable_winrm.ps1"
    }
  SETTINGS

   protected_settings = <<PROTECTED_SETTINGS
    {
      "script": "./scripts/enable_winrm.ps1"
    }
  PROTECTED_SETTINGS
}


# Upload Wazuh agent MSI using WinRM
resource "null_resource" "add_wazuh_agent_msi" {
  depends_on = [azurerm_virtual_machine_extension.web_server_install]

  provisioner "file" {
    source      = "scripts/wazuh-agent-4.9.2-1.msi"  # Path to the local MSI file
    destination = "C:\\Windows\\Temp\\wazuh-agent-4.9.2-1.msi"

    connection {
      type     = "winrm"
      user     = "azureuser"
      password = random_password.password.result  # User password for WinRM
      host     = azurerm_windows_virtual_machine.wazuh_windows_agent_vm.public_ip_address  # Public IP of the VM
      port     = 5985  # Default WinRM HTTP port
      https    = false  # Use HTTP instead of HTTPS
      insecure = true   # Ignore SSL certificate validation (use carefully in production)
    }
  }

  provisioner "remote-exec" {
    inline = [
      "Start-Process -FilePath 'msiexec.exe' -ArgumentList '/i C:\\Windows\\Temp\\wazuh-agent-4.9.2-1.msi ADDRESS=${wazuh_server_linux_ip} /quiet /norestart' -NoNewWindow -Wait",
      "Set-Content -Path 'C:\\Program Files (x86)\\ossec-agent\\ossec.conf' -Value '<ossec>'",
      "Add-Content -Path 'C:\\Program Files (x86)\\ossec-agent\\ossec.conf' -Value '  <server>${wazuh_server_linux_ip}</server>'",
      "Add-Content -Path 'C:\\Program Files (x86)\\ossec-agent\\ossec.conf' -Value '</ossec>'",
      "Start-Service -Name ossec",
      "Set-Service -Name ossec -StartupType Automatic"
    ]

    connection {
      type     = "winrm"
      user     = "azureuser"
      password = random_password.password.result
      host     = azurerm_windows_virtual_machine.wazuh_windows_agent_vm.public_ip_address
      port     = 5985
      https    = false
      insecure = true
    }
  }


   #Provisioner to extract the ZIP and install Sysmon
provisioner "remote-exec" {
    inline = [
      # Extract the Sysmon.zip file using PowerShell
      "powershell -Command 'Expand-Archive -Path C:\\Windows\\Temp\\sysmon.zip -DestinationPath C:\\Windows\\Temp\\sysmon'",

      # Run sysmon.exe with the desired configuration (e.g., sysmon -accepteula -c sysmonconfig.xml)
      "C:\\Windows\\Temp\\sysmon\\sysmon.exe -accepteula -c C:\\Windows\\Temp\\sysmon\\sysmonconfig.xml",

      # Optional: Move the extracted files to a more permanent location
      "move C:\\Windows\\Temp\\sysmon C:\\Program Files\\Sysmon",

      # Clean up the temporary ZIP file
      "Remove-Item C:\\Windows\\Temp\\sysmon.zip"
    ]
    connection {
          type        = "winrm"
          user     = "azureuser"
          password    = random_password.password.result  # Path to your SSH private key
          host        = azurerm_windows_virtual_machine.wazuh_windows_agent_vm.public_ip_address  # Public IP of the VM
          port        = 5985                               # Default WinRM HTTPS port
          https       = false                               # Enable HTTPS for WinRM
          insecure    = true                               # Ignore SSL certificate validation
    }
  } 
}
  
resource "random_password" "password" {
  length      = 20
  min_lower   = 1
  min_upper   = 1
  min_numeric = 1
  min_special = 1
  special     = true
}

