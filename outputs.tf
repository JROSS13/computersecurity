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
