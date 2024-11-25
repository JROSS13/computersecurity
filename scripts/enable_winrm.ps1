# Enable WinRM
Set-Item -Path "WSMan:\localhost\Service\AllowUnencrypted" -Value True
Set-Item -Path "WSMan:\localhost\Service\Auth\Basic" -Value True
Enable-PSRemoting -Force
winrm quickconfig -Force

# Configure the firewall for WinRM
New-NetFirewallRule -Name "WinRM-HTTP" -DisplayName "WinRM over HTTP" -Enabled True -Profile Any -Direction Inbound -Action Allow -Protocol TCP -LocalPort 5985

# Set LocalAccountTokenFilterPolicy for remote admin access
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LocalAccountTokenFilterPolicy" -Value 1 -PropertyType DWord -Force
