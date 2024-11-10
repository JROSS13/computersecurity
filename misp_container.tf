# resource "azurerm_linux_virtual_machine" "misp_vm" {
#   name                = "misp-vm"
#   resource_group_name = azurerm_resource_group.rg.name
#   location            = azurerm_resource_group.rg.location
#   size                = "Standard_B1ms"
#   admin_username      = "azureuser"
#   network_interface_ids = [azurerm_network_interface.misp_nic.id]
#   admin_password      = "YourPasswordHere!"

#   custom_data = <<EOF
# #!/bin/bash
# # Install Docker
# sudo apt update
# sudo apt install -y docker.io
# sudo systemctl enable --now docker

# # Install Git
# sudo apt install -y git

# # Clone git MISP
# git clone git@github.com:MISP/misp-docker.git
# cp temnplate.env .env
# docker compose pull
# docker compuose up


# # Configure CIRCL feeds
# # Place your configuration for CIRCL feeds here

# # Make sure MISP is running
# docker ps
# EOF

#     os_disk {
#         caching              = "ReadWrite"
#         storage_account_type = "Standard_LRS"
#     }
# }
