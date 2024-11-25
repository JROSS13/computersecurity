# Output VM IPs for further configuration
output "misp_ip" {
  value = azurerm_linux_virtual_machine.misp_vm.public_ip_address
}

output "wazuh_linux_ip" {
  value = azurerm_linux_virtual_machine.wazuh_linux_vm.public_ip_address
}

output "server_linux_ip" {
  value = azurerm_linux_virtual_machine.wazuh_server.public_ip_address
}



output "misp_private_ip" {
  value= azurerm_linux_virtual_machine.misp_vm.private_ip_address
  
}

output "admin_password" {
  sensitive = true
  value     = azurerm_windows_virtual_machine.wazuh_windows_agent_vm.admin_password
}
# output "indexer_username" {
#   value = chomp(regex("indexer_username: '(.*)'", file("./admin_credentials.txt"), 1))
# }

# output "indexer_password" {
#   value = chomp(regex("indexer_password: '(.*)'", file("./admin_credentials.txt"), 1))
#   sensitive = true
# }
