#!/bin/bash
# Install Wazuh Agent
curl -s https://packages.wazuh.com/4.x/apt/doc/apt-key.gpg | sudo apt-key add -
echo "deb https://packages.wazuh.com/4.x/apt stable main" | sudo tee /etc/apt/sources.list.d/wazuh.list
sudo apt update
sudo apt install wazuh-agent

# Configure Wazuh agent to interact with MISP using the API key
API_KEY=$(az keyvault secret show --name misp-api-key --vault-name ${azurerm_key_vault.kv.name} --query value -o tsv)
sudo sed -i "s/your-misp-api-key/${API_KEY}/" /var/ossec/etc/ossec.conf
sudo systemctl start wazuh-agent
