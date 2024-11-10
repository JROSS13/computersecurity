#!/bin/bash
sudo apt update
sudo apt install -y curl gnupg
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo apt-key add -
echo "deb https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee -a /etc/apt/sources.list.d/wazuh.list
sudo apt update
sudo apt install wazuh-manager
sudo systemctl enable wazuh-manager
sudo systemctl start wazuh-manager
