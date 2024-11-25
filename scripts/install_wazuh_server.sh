#!/bin/bash

sudo apt update -y
sudo apt install -y curl gnupg
curl -sO https://packages.wazuh.com/4.9/wazuh-install.sh
curl -sO https://packages.wazuh.com/4.9/config.yml
# have to add ips to config file before next step
bash wazuh-install.sh --generate-config-files
curl -sO https://packages.wazuh.com/4.9/wazuh-install.sh
bash wazuh-install.sh --wazuh-indexer node-1
bash wazuh-install.sh --start-cluster
tar -axf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt -O | grep -P "\'admin\'" -A 1
bash wazuh-install.sh --wazuh-server wazuh-1
bash wazuh-install.sh --wazuh-dashboard dashboard
sudo tar -axf wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt -O | grep -P "\'admin\'" -A 1 >> required.txt