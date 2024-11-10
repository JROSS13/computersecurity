# resource "azurerm_linux_virtual_machine" "wazuh_linux_vm" {
#     name                = "wazuh-linux-vm"
#     resource_group_name = azurerm_resource_group.rg.name
#     location            = azurerm_resource_group.rg.location
#     size                = "Standard_B1ms"
#     admin_username      = "azureuser"
#     network_interface_ids = [azurerm_network_interface.wazuh_nic.id]
#     admin_password      = "YourPasswordHere!"

#   custom_data = file("scripts/install_wazuh_agent.sh")

#     os_disk {
#     caching              = "ReadWrite"
#     storage_account_type = "Standard_LRS"
#   }
# }
