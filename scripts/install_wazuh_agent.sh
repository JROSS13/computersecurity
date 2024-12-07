#!/bin/bash

# Install Wazuh Agent
# Configure Wazuh agent to connect to the Wazuh Manager
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && sudo chmod 644 /usr/share/keyrings/wazuh.gpg
sudo echo 'deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main' | sudo tee -a /etc/apt/sources.list.d/wazuh.list
sudo apt-get -y update
sudo WAZUH_MANAGER=${wazuh_server_linux_ip} apt-get install -y wazuh-agent

sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent

