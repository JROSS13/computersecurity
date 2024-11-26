# Install the Wazuh agent silently
# "Invoke-WebRequest -Uri 'https://packages.wazuh.com/4.9/windows/wazuh-agent-4.9.2-1.msi' -OutFile 'C:\\Windows\\Temp\\wazuh-agent-4.9.2-1.msi'",
  
# Install the Wazuh agent silently
"Start-Process -FilePath 'msiexec.exe' -ArgumentList '/i C:\\Windows\\Temp\\wazuh_windows_agent\\wazuh-agent-4.9.2-1.msi ADDRESS=${wazuh_server_linux_ip}' /quiet /norestart' -NoNewWindow -Wait",

# Configure the agent to connect to the Wazuh manager
"Set-Content -Path 'C:\\Program Files (x86)\\ossec-agent\\ossec.conf' -Value '<ossec>'",
"Add-Content -Path 'C:\\Program Files (x86)\\ossec-agent\\ossec.conf' -Value '  <server>${wazuh_server_linux_ip}</server>'",
"Add-Content -Path 'C:\\Program Files (x86)\\ossec-agent\\ossec.conf' -Value '</ossec>'",

# Start the Wazuh agent service
"Start-Service -Name ossec",

# Enable the agent to start on boot
"Set-Service -Name ossec -StartupType Automatic"